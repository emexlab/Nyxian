/* SPDX-License-Identifier: GPL-3.0-or-later
 * The TWRP terminal of the Nyxian recovery (upstream gui/terminal.cpp's role).
 *
 * The session is process wide, like upstream's TerminalEngine: leaving the
 * terminal page keeps the shell running, coming back shows it again. A small
 * VT100/xterm subset emulator (cursor movement, erasing, scroll regions,
 * SGR colors incl. 256/true color, the alternate screen, application cursor
 * keys, DSR/DA answers) is enough for bash, readline, vi, less-alikes and
 * the ncurses tools of the binpack.
 */
#import <Foundation/Foundation.h>
#include "NXTWRPTerminal.hpp"
#include "Upstream/gui/objects.hpp"
#include "Upstream/NXTWRPBridge.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <cmath>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define KEY_LEFT 105
#define KEY_RIGHT 106
#define KEY_UP 103
#define KEY_DOWN 108

namespace {

constexpr uint16_t kDefaultColor = 0xFFFF;
constexpr size_t kHistoryLines = 1000;

enum : uint8_t { AttrBold = 1, AttrDim = 2, AttrItalic = 4, AttrUnderline = 8, AttrInverse = 16 };

struct Cell {
    uint32_t ch = ' ';
    uint16_t fg = kDefaultColor;
    uint16_t bg = kDefaultColor;
    uint8_t attr = 0;
};

using Line = std::vector<Cell>;

/* ----------------------------------------------------------------------
 *  emulator
 * -------------------------------------------------------------------- */

class Emulator {
public:
    int cols = 80, rows = 24;
    std::vector<Line> main, alt;
    std::deque<Line> history;
    bool usingAlt = false;
    int cx = 0, cy = 0;
    bool wrapNext = false;
    int top = 0, bottom = 23;
    Cell pen;
    struct Saved { int cx = 0, cy = 0; Cell pen; bool wrapNext = false; } saved, savedAlt;
    bool cursorVisible = true, appCursor = false, autowrap = true, originMode = false;
    std::string responses;

    Emulator() { reset(); }

    std::vector<Line>& screen() { return usingAlt ? alt : main; }

    Cell blank() const { Cell c; c.bg = pen.bg; return c; }

    void reset() {
        main.assign(rows, Line(cols));
        alt.assign(rows, Line(cols));
        usingAlt = false;
        cx = cy = 0; wrapNext = false;
        top = 0; bottom = rows - 1;
        pen = Cell();
        saved = savedAlt = Saved();
        cursorVisible = true; appCursor = false; autowrap = true; originMode = false;
        state = Ground;
    }

    void resize(int newCols, int newRows) {
        newCols = std::max(newCols, 2);
        newRows = std::max(newRows, 2);
        if(newCols == cols && newRows == rows) return;
        for(auto* lines : {&main, &alt}) {
            bool active = (lines == &alt) == usingAlt;
            if((int)lines->size() > newRows) {
                /* shrinking: drop lines above the cursor first (into history), then below it */
                int drop = active ? std::max(0, cy - (newRows - 1)) : 0;
                for(int i = 0; i < drop; i++) {
                    if(lines == &main) pushHistory(lines->front());
                    lines->erase(lines->begin());
                }
                if(active) cy -= drop;
                lines->resize((size_t)newRows);
            }
            while((int)lines->size() < newRows) lines->push_back(Line((size_t)newCols));
            for(auto& line : *lines) line.resize((size_t)newCols);
        }
        for(auto& line : history) line.resize((size_t)newCols);
        cols = newCols; rows = newRows;
        top = 0; bottom = rows - 1;
        cx = std::min(cx, cols - 1); cy = std::clamp(cy, 0, rows - 1);
        wrapNext = false;
    }

    void feed(const char* bytes, size_t length) {
        for(size_t i = 0; i < length; i++) byte((uint8_t)bytes[i]);
    }

private:
    enum State { Ground, Escape, Csi, Osc, OscEscape, Skip } state = Ground;
    std::string params;
    char marker = 0;
    uint32_t utf8 = 0;
    int utf8Need = 0;

    void pushHistory(const Line& line) {
        history.push_back(line);
        while(history.size() > kHistoryLines) history.pop_front();
    }

    void scrollUp(int n) {
        auto& s = screen();
        for(int i = 0; i < n; i++) {
            if(!usingAlt && top == 0) pushHistory(s[top]);
            s.erase(s.begin() + top);
            s.insert(s.begin() + bottom, Line(cols, blank()));
        }
    }

    void scrollDown(int n) {
        auto& s = screen();
        for(int i = 0; i < n; i++) {
            s.erase(s.begin() + bottom);
            s.insert(s.begin() + top, Line(cols, blank()));
        }
    }

    void index() {
        if(cy == bottom) scrollUp(1);
        else if(cy < rows - 1) cy++;
    }

    void reverseIndex() {
        if(cy == top) scrollDown(1);
        else if(cy > 0) cy--;
    }

    void put(uint32_t ch) {
        if(wrapNext && autowrap) {
            cx = 0;
            index();
        }
        wrapNext = false;
        Cell cell = pen;
        cell.ch = ch;
        screen()[cy][cx] = cell;
        if(cx == cols - 1) wrapNext = true;
        else cx++;
    }

    void control(uint8_t c) {
        switch(c) {
            case 0x07: break;
            case 0x08: if(cx > 0) cx--; wrapNext = false; break;
            case 0x09: cx = std::min(cols - 1, (cx / 8 + 1) * 8); wrapNext = false; break;
            case 0x0A: case 0x0B: case 0x0C: index(); wrapNext = false; break;
            case 0x0D: cx = 0; wrapNext = false; break;
            case 0x1B: state = Escape; break;
            default: break;
        }
    }

    void byte(uint8_t c) {
        switch(state) {
            case Ground:
                if(utf8Need > 0) {
                    if((c & 0xC0) == 0x80) {
                        utf8 = (utf8 << 6) | (c & 0x3F);
                        if(--utf8Need == 0) put(utf8);
                        return;
                    }
                    utf8Need = 0;
                    put(0xFFFD);
                }
                if(c < 0x20 || c == 0x7F) { if(c != 0x7F) control(c); return; }
                if(c < 0x80) { put(c); return; }
                if((c & 0xE0) == 0xC0) { utf8 = c & 0x1F; utf8Need = 1; }
                else if((c & 0xF0) == 0xE0) { utf8 = c & 0x0F; utf8Need = 2; }
                else if((c & 0xF8) == 0xF0) { utf8 = c & 0x07; utf8Need = 3; }
                else put(0xFFFD);
                return;
            case Escape:
                state = Ground;
                switch(c) {
                    case '[': state = Csi; params.clear(); marker = 0; break;
                    case ']': case 'P': case '_': case '^': state = Osc; break;
                    case '(': case ')': case '*': case '+': case '#': case '%': state = Skip; break;
                    case '7': saveCursor(); break;
                    case '8': restoreCursor(); break;
                    case 'D': index(); break;
                    case 'E': cx = 0; index(); break;
                    case 'M': reverseIndex(); break;
                    case 'c': reset(); break;
                    default: break;
                }
                return;
            case Skip:
                state = Ground;
                return;
            case Osc:
                if(c == 0x07) state = Ground;
                else if(c == 0x1B) state = OscEscape;
                return;
            case OscEscape:
                state = c == '\\' ? Ground : Osc;
                return;
            case Csi:
                if(c >= 0x30 && c <= 0x3F) {
                    if(params.empty() && (c == '?' || c == '>' || c == '=' || c == '<')) marker = (char)c;
                    else params.push_back((char)c);
                    return;
                }
                if(c >= 0x20 && c <= 0x2F) return;
                if(c < 0x20) { control(c); return; }
                state = Ground;
                csi((char)c);
                return;
        }
    }

    std::vector<int> args() const {
        std::vector<int> out;
        std::string current;
        for(char ch : params + ";") {
            if(ch == ';' || ch == ':') {
                out.push_back(current.empty() ? -1 : atoi(current.c_str()));
                current.clear();
            } else current.push_back(ch);
        }
        return out;
    }

    static int arg(const std::vector<int>& a, size_t i, int def) {
        return i < a.size() && a[i] > 0 ? a[i] : def;
    }

    void saveCursor() {
        Saved& s = usingAlt ? savedAlt : saved;
        s.cx = cx; s.cy = cy; s.pen = pen; s.wrapNext = wrapNext;
    }

    void restoreCursor() {
        Saved& s = usingAlt ? savedAlt : saved;
        cx = std::min(s.cx, cols - 1); cy = std::min(s.cy, rows - 1); pen = s.pen; wrapNext = s.wrapNext;
    }

    void eraseCells(int row, int from, int to) {
        auto& line = screen()[row];
        for(int x = std::max(0, from); x < std::min(cols, to); x++) line[x] = blank();
    }

    void setAlt(bool enable, bool clear) {
        if(enable == usingAlt) return;
        usingAlt = enable;
        if(enable && clear) alt.assign(rows, Line(cols, blank()));
    }

    void mode(bool set, const std::vector<int>& a) {
        for(int value : a) {
            if(marker == '?') {
                switch(value) {
                    case 1: appCursor = set; break;
                    case 6: originMode = set; cx = 0; cy = set ? top : 0; break;
                    case 7: autowrap = set; break;
                    case 25: cursorVisible = set; break;
                    case 47: case 1047: setAlt(set, set); break;
                    case 1048: set ? saveCursor() : restoreCursor(); break;
                    case 1049:
                        if(set) { saveCursor(); setAlt(true, true); }
                        else { setAlt(false, false); restoreCursor(); }
                        break;
                    default: break;
                }
            }
        }
    }

    static uint16_t rgbToIndex(int r, int g, int b) {
        auto level = [](int v) { return v < 48 ? 0 : v < 115 ? 1 : (v - 35) / 40; };
        return (uint16_t)(16 + 36 * level(r) + 6 * level(g) + level(b));
    }

    void sgr(const std::vector<int>& a) {
        if(a.empty()) { pen = Cell(); return; }
        for(size_t i = 0; i < a.size(); i++) {
            int v = a[i] < 0 ? 0 : a[i];
            if(v == 0) { uint32_t keep = pen.ch; pen = Cell(); pen.ch = keep; }
            else if(v == 1) pen.attr |= AttrBold;
            else if(v == 2) pen.attr |= AttrDim;
            else if(v == 3) pen.attr |= AttrItalic;
            else if(v == 4) pen.attr |= AttrUnderline;
            else if(v == 7) pen.attr |= AttrInverse;
            else if(v == 22) pen.attr &= ~(AttrBold | AttrDim);
            else if(v == 23) pen.attr &= ~AttrItalic;
            else if(v == 24) pen.attr &= ~AttrUnderline;
            else if(v == 27) pen.attr &= ~AttrInverse;
            else if(v >= 30 && v <= 37) pen.fg = (uint16_t)(v - 30);
            else if(v == 39) pen.fg = kDefaultColor;
            else if(v >= 40 && v <= 47) pen.bg = (uint16_t)(v - 40);
            else if(v == 49) pen.bg = kDefaultColor;
            else if(v >= 90 && v <= 97) pen.fg = (uint16_t)(v - 90 + 8);
            else if(v >= 100 && v <= 107) pen.bg = (uint16_t)(v - 100 + 8);
            else if(v == 38 || v == 48) {
                uint16_t color = kDefaultColor;
                if(i + 2 < a.size() && a[i + 1] == 5) { color = (uint16_t)std::clamp(a[i + 2], 0, 255); i += 2; }
                else if(i + 4 < a.size() && a[i + 1] == 2) { color = rgbToIndex(a[i + 2], a[i + 3], a[i + 4]); i += 4; }
                (v == 38 ? pen.fg : pen.bg) = color;
            }
        }
    }

    void csi(char final) {
        std::vector<int> a = args();
        int n = arg(a, 0, 1);
        auto& s = screen();
        wrapNext = final == 'm' ? wrapNext : false;
        switch(final) {
            case 'A': cy = std::max(cy >= top ? top : 0, cy - n); break;
            case 'B': case 'e': cy = std::min(cy <= bottom ? bottom : rows - 1, cy + n); break;
            case 'C': case 'a': cx = std::min(cols - 1, cx + n); break;
            case 'D': cx = std::max(0, cx - n); break;
            case 'E': cx = 0; cy = std::min(rows - 1, cy + n); break;
            case 'F': cx = 0; cy = std::max(0, cy - n); break;
            case 'G': case '`': cx = std::clamp(n - 1, 0, cols - 1); break;
            case 'd': cy = std::clamp(n - 1 + (originMode ? top : 0), 0, rows - 1); break;
            case 'H': case 'f':
                cy = std::clamp(arg(a, 0, 1) - 1 + (originMode ? top : 0), 0, rows - 1);
                cx = std::clamp(arg(a, 1, 1) - 1, 0, cols - 1);
                break;
            case 'J': {
                int how = a.empty() || a[0] < 0 ? 0 : a[0];
                if(how == 0) { eraseCells(cy, cx, cols); for(int y = cy + 1; y < rows; y++) eraseCells(y, 0, cols); }
                else if(how == 1) { eraseCells(cy, 0, cx + 1); for(int y = 0; y < cy; y++) eraseCells(y, 0, cols); }
                else { for(int y = 0; y < rows; y++) eraseCells(y, 0, cols); if(how == 3 && !usingAlt) history.clear(); }
                break;
            }
            case 'K': {
                int how = a.empty() || a[0] < 0 ? 0 : a[0];
                if(how == 0) eraseCells(cy, cx, cols);
                else if(how == 1) eraseCells(cy, 0, cx + 1);
                else eraseCells(cy, 0, cols);
                break;
            }
            case '@': { auto& line = s[cy]; n = std::min(n, cols - cx); line.insert(line.begin() + cx, n, blank()); line.resize(cols); break; }
            case 'P': { auto& line = s[cy]; n = std::min(n, cols - cx); line.erase(line.begin() + cx, line.begin() + cx + n); line.resize(cols, blank()); break; }
            case 'X': eraseCells(cy, cx, cx + n); break;
            case 'L':
                if(cy >= top && cy <= bottom) for(int i = 0; i < n; i++) { s.erase(s.begin() + bottom); s.insert(s.begin() + cy, Line(cols, blank())); }
                cx = 0;
                break;
            case 'M':
                if(cy >= top && cy <= bottom) for(int i = 0; i < n; i++) { s.erase(s.begin() + cy); s.insert(s.begin() + bottom, Line(cols, blank())); }
                cx = 0;
                break;
            case 'S': scrollUp(n); break;
            case 'T': if(marker == 0) scrollDown(n); break;
            case 'r': {
                int t = arg(a, 0, 1) - 1, b = arg(a, 1, rows) - 1;
                if(t < b && b < rows) { top = t; bottom = b; }
                else { top = 0; bottom = rows - 1; }
                cx = 0; cy = originMode ? top : 0;
                break;
            }
            case 'm': if(marker == 0) sgr(a.size() == 1 && a[0] < 0 ? std::vector<int>() : a); break;
            case 'h': mode(true, a); break;
            case 'l': mode(false, a); break;
            case 's': saveCursor(); break;
            case 'u': restoreCursor(); break;
            case 'n':
                if(arg(a, 0, 0) == 6) {
                    char reply[32];
                    snprintf(reply, sizeof(reply), "\x1b[%d;%dR", cy + 1 - (originMode ? top : 0), cx + 1);
                    responses += reply;
                } else if(arg(a, 0, 0) == 5) {
                    responses += "\x1b[0n";
                }
                break;
            case 'c':
                if(marker == 0) responses += "\x1b[?1;2c";
                else if(marker == '>') responses += "\x1b[>0;0;0c";
                break;
            default:
                break;
        }
    }
};

/* ----------------------------------------------------------------------
 *  session
 * -------------------------------------------------------------------- */

struct Session {
    std::mutex mutex;
    Emulator vt;
    int fd = -1;
    pid_t pid = -1;
    bool ended = false;
    /* the TTY hung up (reader saw EOF) / the kernel reported the shell's wait status */
    bool hungup = false;
    bool exitKnown = false;
    int exitStatus = 0;
    /* shells that exited before NXTWRPTerminalAttach saw their pid */
    std::map<pid_t, int> earlyExits;
    int scroll = 0;
    /* when the shell last wrote something: input queued for it waits until it went quiet (its prompt) */
    bool outputSeen = false;
    std::chrono::steady_clock::time_point lastOutput;
    std::atomic<bool> launching{false};
    NXTWRPTerminalLauncher launcher = nullptr;
    NXTWRPTerminalResizer resizer = nullptr;
};

Session& session() {
    static Session* s = new Session();
    return *s;
}

void writeAll(int fd, const char* bytes, size_t length) {
    size_t off = 0;
    while(off < length) {
        ssize_t n = write(fd, bytes + off, length - off);
        if(n > 0) { off += (size_t)n; continue; }
        if(n < 0 && errno == EINTR) continue;
        return;
    }
}

void printLocked(Session& s, const char* text) {
    s.vt.feed(text, strlen(text));
}

/* the session is over: says why, once the TTY drained and (ideally) the exit status is in */
void finishLocked(Session& s) {
    if(s.ended) return;
    s.ended = true;
    char line[160];
    if(!s.exitKnown) snprintf(line, sizeof(line), "\r\n[terminal closed, press any key for a new shell]\r\n");
    else if(WIFSIGNALED(s.exitStatus)) snprintf(line, sizeof(line), "\r\n[shell (pid %d) killed by signal %d (%s), press any key for a new shell]\r\n", s.pid, WTERMSIG(s.exitStatus), strsignal(WTERMSIG(s.exitStatus)));
    else snprintf(line, sizeof(line), "\r\n[shell (pid %d) exited with status %d, press any key for a new shell]\r\n", s.pid, WEXITSTATUS(s.exitStatus));
    printLocked(s, line);
}

void reader(int fd) {
    pthread_setname_np("TWRP terminal");
    std::vector<char> buffer(65536);
    for(;;) {
        ssize_t n = read(fd, buffer.data(), buffer.size());
        if(n > 0) {
            std::string responses;
            {
                std::lock_guard<std::mutex> lock(session().mutex);
                session().vt.feed(buffer.data(), (size_t)n);
                session().scroll = 0;
                session().outputSeen = true;
                session().lastOutput = std::chrono::steady_clock::now();
                responses.swap(session().vt.responses);
            }
            if(!responses.empty()) writeAll(fd, responses.data(), responses.size());
            continue;
        }
        if(n < 0 && errno == EINTR) continue;
        break;
    }
    Session& s = session();
    pid_t pid = -1;
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        if(s.fd == fd) {
            /* the TTY hung up, usually the shell is gone: give the kernel a moment to report how it ended */
            s.fd = -1;
            s.hungup = true;
            pid = s.pid;
            if(s.exitKnown) finishLocked(s);
        }
    }
    close(fd);
    if(pid < 0) return;
    for(int i = 0; i < 30; i++) {
        {
            std::lock_guard<std::mutex> lock(s.mutex);
            if(s.pid != pid || s.ended) return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::lock_guard<std::mutex> lock(s.mutex);
    if(s.pid == pid) finishLocked(s);
}

void launchAsync() {
    Session& s = session();
    if(s.launcher == nullptr || s.launching.exchange(true)) return;
    NXTWRPTerminalLauncher launcher = s.launcher;
    std::thread([launcher] {
        launcher();     /* reports its own failures on the terminal */
        session().launching = false;
    }).detach();
}

void send(const std::string& bytes) {
    if(bytes.empty()) return;
    Session& s = session();
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        s.scroll = 0;
        /* our own reference: writing must never hold the lock the reader needs to drain the output */
        if(s.fd >= 0) fd = dup(s.fd);
    }
    if(fd >= 0) {
        writeAll(fd, bytes.data(), bytes.size());
        close(fd);
        return;
    }
    launchAsync();
}

std::string utf8(uint32_t cp) {
    std::string out;
    if(cp < 0x80) out.push_back((char)cp);
    else if(cp < 0x800) { out.push_back((char)(0xC0 | (cp >> 6))); out.push_back((char)(0x80 | (cp & 0x3F))); }
    else if(cp < 0x10000) { out.push_back((char)(0xE0 | (cp >> 12))); out.push_back((char)(0x80 | ((cp >> 6) & 0x3F))); out.push_back((char)(0x80 | (cp & 0x3F))); }
    else { out.push_back((char)(0xF0 | (cp >> 18))); out.push_back((char)(0x80 | ((cp >> 12) & 0x3F))); out.push_back((char)(0x80 | ((cp >> 6) & 0x3F))); out.push_back((char)(0x80 | (cp & 0x3F))); }
    return out;
}

std::string keySequence(int key) {
    Session& s = session();
    bool app;
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        app = s.vt.appCursor;
    }
    switch(key) {
        case NXTWRPTerminalKeyUp: return app ? "\x1bOA" : "\x1b[A";
        case NXTWRPTerminalKeyDown: return app ? "\x1bOB" : "\x1b[B";
        case NXTWRPTerminalKeyRight: return app ? "\x1bOC" : "\x1b[C";
        case NXTWRPTerminalKeyLeft: return app ? "\x1bOD" : "\x1b[D";
        case NXTWRPTerminalKeyHome: return app ? "\x1bOH" : "\x1b[H";
        case NXTWRPTerminalKeyEnd: return app ? "\x1bOF" : "\x1b[F";
        case NXTWRPTerminalKeyPageUp: return "\x1b[5~";
        case NXTWRPTerminalKeyPageDown: return "\x1b[6~";
        case NXTWRPTerminalKeyDelete: return "\x1b[3~";
        case NXTWRPTerminalKeyEscape: return "\x1b";
        case NXTWRPTerminalKeyTab: return "\t";
        case NXTWRPTerminalKeyBackspace: return "\x7f";
        case NXTWRPTerminalKeyReturn: return "\r";
        default: return "";
    }
}

/* xterm's default palette */
COLOR paletteColor(uint16_t index) {
    static const unsigned char base[16][3] = {
        {0,0,0},{205,0,0},{0,205,0},{205,205,0},{0,0,238},{205,0,205},{0,205,205},{229,229,229},
        {127,127,127},{255,0,0},{0,255,0},{255,255,0},{92,92,255},{255,0,255},{0,255,255},{255,255,255},
    };
    if(index < 16) return COLOR(base[index][0], base[index][1], base[index][2]);
    if(index < 232) {
        int i = index - 16;
        auto level = [](int v) { return v == 0 ? 0 : 55 + v * 40; };
        return COLOR((unsigned char)level(i / 36), (unsigned char)level((i / 6) % 6), (unsigned char)level(i % 6));
    }
    int gray = 8 + (index - 232) * 10;
    return COLOR((unsigned char)gray, (unsigned char)gray, (unsigned char)gray);
}

/* ----------------------------------------------------------------------
 *  <terminal> object
 * -------------------------------------------------------------------- */

class NXTerminal : public GUIObject, public RenderObject, public ActionObject, public InputObject {
    FontResource* mFont = nullptr;
    COLOR mForeground = COLOR(255, 255, 255);
    COLOR mBackground = COLOR(0, 0, 0);
    double mCellW = 16;
    int mLineH = 32;
    int mTouchY = 0, mTouchLines = 0;

public:
    NXTerminal(xml_node<>* node) : GUIObject(node) {
        LoadPlacement(FindNode(node, "placement"), &mRenderX, &mRenderY, &mRenderW, &mRenderH);
        SetActionPos(mRenderX, mRenderY, mRenderW, mRenderH);
        xml_node<>* font = FindNode(node, "font");
        mFont = LoadAttrFont(font, "resource");
        mForeground = LoadAttrColor(font, "color", mForeground);
        mBackground = LoadAttrColor(FindNode(node, "background"), "color", mBackground);
        int spacing = LoadAttrIntScaleY(font, "spacing", 0);
        if(mFont && mFont->GetResource()) {
            std::string sample(100, 'M');
            mCellW = std::max(1.0, twrpTruetype::gr_ttf_measureEx(sample.c_str(), mFont->GetResource()) / 100.0);
            mLineH = std::max(1, mFont->GetHeight() + spacing);
        }
    }

    int IsInRegion(int x, int y) override {
        return isConditionTrue() && ActionObject::IsInRegion(x, y);
    }

    int SetRenderPos(int x, int y, int w, int h) override {
        RenderObject::SetRenderPos(x, y, w, h);
        SetActionPos(mRenderX, mRenderY, mRenderW, mRenderH);
        return 0;
    }

    int Update() override { return 0; }

    int Render() override {
        if(!isConditionTrue()) return 0;
        gr_color(mBackground.red, mBackground.green, mBackground.blue, 255);
        gr_fill(mRenderX, mRenderY, mRenderW, mRenderH);
        if(!mFont || !mFont->GetResource()) return 0;

        int cols = std::max(10, (int)floor((mRenderW - 16) / mCellW));
        int rows = std::max(4, mRenderH / mLineH);
        int left = mRenderX + 8;

        Session& s = session();
        std::vector<Line> lines;
        int cursorX = -1, cursorY = -1;
        int fd = -1;
        bool resized = false;
        {
            std::lock_guard<std::mutex> lock(s.mutex);
            if(s.vt.cols != cols || s.vt.rows != rows) {
                s.vt.resize(cols, rows);
                resized = true;
            }
            fd = s.fd;
            Emulator& vt = s.vt;
            int history = vt.usingAlt ? 0 : (int)vt.history.size();
            s.scroll = std::clamp(s.scroll, 0, history);
            int first = history - s.scroll;     /* index into history ++ screen */
            for(int r = 0; r < vt.rows; r++) {
                int index = first + r;
                if(index < history) lines.push_back(vt.history[(size_t)index]);
                else lines.push_back(vt.screen()[(size_t)(index - history)]);
            }
            if(s.scroll == 0 && vt.cursorVisible && fd >= 0) {
                cursorX = vt.cx;
                cursorY = vt.cy;
            }
        }
        if(resized && fd >= 0 && s.resizer) s.resizer(fd, (unsigned short)rows, (unsigned short)cols);

        for(int r = 0; r < (int)lines.size(); r++) {
            const Line& line = lines[(size_t)r];
            int y = mRenderY + r * mLineH;
            int c = 0;
            while(c < (int)line.size()) {
                const Cell& first = line[(size_t)c];
                int end = c + 1;
                while(end < (int)line.size() && line[(size_t)end].fg == first.fg && line[(size_t)end].bg == first.bg &&
                      line[(size_t)end].attr == first.attr) end++;
                drawRun(line, c, end, left, y, r == cursorY ? cursorX : -1);
                c = end;
            }
        }
        if(cursorX >= 0 && cursorY >= 0 && cursorY < (int)lines.size()) {
            int x = left + (int)lround(cursorX * mCellW);
            int y = mRenderY + cursorY * mLineH;
            gr_color(mForeground.red, mForeground.green, mForeground.blue, 160);
            gr_fill(x, y + mLineH - std::max(4, mLineH / 8), std::max(2, (int)lround(mCellW)), std::max(4, mLineH / 8));
        }
        return 0;
    }

    int NotifyTouch(TOUCH_STATE state, int x, int y) override {
        if(!isConditionTrue()) return 1;
        Session& s = session();
        if(state == TOUCH_START) { mTouchY = y; mTouchLines = 0; return 0; }
        if(state == TOUCH_DRAG && x != -10000) {
            int lines = (y - mTouchY) / std::max(1, mLineH);
            if(lines != mTouchLines) {
                std::lock_guard<std::mutex> lock(s.mutex);
                s.scroll += lines - mTouchLines;
                mTouchLines = lines;
            }
        }
        return 0;
    }

    int NotifyKey(int key, bool down) override {
        if(!isConditionTrue()) return 1;
        if(!down) return 0;
        switch(key) {
            case KEY_UP: send(keySequence(NXTWRPTerminalKeyUp)); return 0;
            case KEY_DOWN: send(keySequence(NXTWRPTerminalKeyDown)); return 0;
            case KEY_LEFT: send(keySequence(NXTWRPTerminalKeyLeft)); return 0;
            case KEY_RIGHT: send(keySequence(NXTWRPTerminalKeyRight)); return 0;
            default: return 1;
        }
    }

    int NotifyCharInput(int ch) override {
        if(!isConditionTrue()) return 1;
        if(ch == KEYBOARD_ACTION) send("\r");
        else if(ch == KEYBOARD_BACKSPACE) send("\x7f");
        else if(ch > 0) send(utf8((uint32_t)ch));
        return 0;
    }

private:
    void drawRun(const Line& line, int from, int to, int left, int y, int cursorX) {
        const Cell& cell = line[(size_t)from];
        uint16_t fgIndex = cell.fg, bgIndex = cell.bg;
        if((cell.attr & AttrBold) && fgIndex < 8) fgIndex += 8;
        COLOR fg = fgIndex == kDefaultColor ? mForeground : paletteColor(fgIndex);
        COLOR bg = bgIndex == kDefaultColor ? mBackground : paletteColor(bgIndex);
        if(cell.attr & AttrInverse) std::swap(fg, bg);
        if(cell.attr & AttrDim) { fg.red /= 2; fg.green /= 2; fg.blue /= 2; }

        int x0 = left + (int)lround(from * mCellW);
        int x1 = left + (int)lround(to * mCellW);
        if(bgIndex != kDefaultColor || (cell.attr & AttrInverse)) {
            gr_color(bg.red, bg.green, bg.blue, 255);
            gr_fill(x0, y, x1 - x0, mLineH);
        }

        std::string text;
        int last = to;
        while(last > from && line[(size_t)last - 1].ch == ' ') last--;
        for(int i = from; i < last; i++) text += utf8(line[(size_t)i].ch);
        if(!text.empty()) {
            gr_color(fg.red, fg.green, fg.blue, 255);
            gr_textEx_scaleW(x0, y, text.c_str(), mFont->GetResource(), 0, TOP_LEFT, 0);
        }
        if(cell.attr & AttrUnderline) {
            gr_color(fg.red, fg.green, fg.blue, 255);
            gr_fill(x0, y + mLineH - 3, x1 - x0, 2);
        }
        (void)cursorX;
    }
};

}  // namespace

GUIObject *nx_twrp_terminal(xml_node<>* node) { return new NXTerminal(node); }

void NXTWRPTerminalSetLauncher(NXTWRPTerminalLauncher launcher, NXTWRPTerminalResizer resizer) {
    std::lock_guard<std::mutex> lock(session().mutex);
    session().launcher = launcher;
    session().resizer = resizer;
}

void NXTWRPTerminalAttach(int masterFD, pid_t pid) {
    Session& s = session();
    int old;
    unsigned short rows, cols;
    {
        std::lock_guard<std::mutex> lock(s.mutex);
        old = s.fd;
        s.fd = masterFD;
        s.pid = pid;
        s.ended = false;
        s.hungup = false;
        s.exitKnown = false;
        auto early = s.earlyExits.find(pid);
        if(early != s.earlyExits.end()) {
            s.exitKnown = true;
            s.exitStatus = early->second;
            s.earlyExits.erase(early);
        }
        s.scroll = 0;
        s.outputSeen = false;
        rows = (unsigned short)s.vt.rows;
        cols = (unsigned short)s.vt.cols;
    }
    if(old >= 0) shutdown(old, SHUT_RDWR);  /* its reader closes it */
    if(s.resizer) s.resizer(masterFD, rows, cols);
    std::thread(reader, masterFD).detach();
}

bool NXTWRPTerminalAttached(void) {
    std::lock_guard<std::mutex> lock(session().mutex);
    return session().fd >= 0 && !session().ended;
}

void NXTWRPTerminalSessionEnded(pid_t pid, int status) {
    Session& s = session();
    std::lock_guard<std::mutex> lock(s.mutex);
    if(pid != s.pid) {
        /* the shell may die before its pid reaches NXTWRPTerminalAttach */
        if(s.earlyExits.size() >= 16) s.earlyExits.erase(s.earlyExits.begin());
        s.earlyExits[pid] = status;
        return;
    }
    if(s.ended || s.exitKnown) return;
    s.exitKnown = true;
    s.exitStatus = status;
    if(s.hungup) {
        finishLocked(s);
        return;
    }
    /* let the reader drain what the shell wrote last, then hang up if a background job still holds the TTY */
    int fd = s.fd;
    std::thread([pid, fd] {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        Session& s = session();
        std::lock_guard<std::mutex> lock(s.mutex);
        if(s.pid == pid && s.fd == fd && fd >= 0 && !s.ended) shutdown(fd, SHUT_RDWR);  /* the reader finishes it */
    }).detach();
}

void NXTWRPTerminalSize(unsigned short *rows, unsigned short *cols) {
    std::lock_guard<std::mutex> lock(session().mutex);
    if(rows) *rows = (unsigned short)session().vt.rows;
    if(cols) *cols = (unsigned short)session().vt.cols;
}

void NXTWRPTerminalSendText(const char *text, size_t length) {
    if(text && length) send(std::string(text, length));
}

void NXTWRPTerminalSendCommand(const char *text) {
    if(text == nullptr || *text == 0) return;
    std::string bytes(text);
    std::thread([bytes] {
        pthread_setname_np("TWRP terminal command");
        using namespace std::chrono;
        Session& s = session();
        /* typed into a shell that is still starting, the line would be echoed by the TTY and again by readline */
        auto deadline = steady_clock::now() + seconds(5);
        for(;;) {
            {
                std::lock_guard<std::mutex> lock(s.mutex);
                if(s.fd < 0 || s.ended) return;
                if((s.outputSeen && steady_clock::now() - s.lastOutput >= milliseconds(250)) || steady_clock::now() >= deadline) break;
            }
            std::this_thread::sleep_for(milliseconds(50));
        }
        send(bytes);
    }).detach();
}

void NXTWRPTerminalSendKey(int key) {
    send(keySequence(key));
}

void NXTWRPTerminalPrint(const char *text) {
    if(!text) return;
    std::lock_guard<std::mutex> lock(session().mutex);
    printLocked(session(), text);
}
