/* SPDX-License-Identifier: GPL-3.0-or-later
 * Persistent, bounded TWRP ZIP import. Archives never write outside a new owned directory.
 */
#import "NXTWRPThemeStore.h"
#include "NXTWRPEngine.hpp"
#include <sys/stat.h>
extern "C" {
struct archive; struct archive_entry;
archive *archive_read_new(void);
int archive_read_support_format_zip(archive *);
int archive_read_open_filename(archive *,const char *,size_t);
int archive_read_next_header(archive *,archive_entry **);
const char *archive_entry_pathname(archive_entry *);
unsigned int archive_entry_filetype(archive_entry *);
const char *archive_entry_symlink(archive_entry *);
const char *archive_entry_hardlink(archive_entry *);
int64_t archive_entry_size(archive_entry *);
ssize_t archive_read_data(archive *,void *,size_t);
int archive_read_free(archive *);
}
NSNotificationName const NXTWRPThemeDidChangeNotification=@"NXTWRPThemeDidChange";
static NSString *const PathKey=@"org.emexlabs.nyxian.recovery.theme.path";
static NSString *const NameKey=@"org.emexlabs.nyxian.recovery.theme.name";
static NSError *ThemeError(NSString *message) {return [NSError errorWithDomain:@"NXTWRPTheme" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];}
static NSURL *ThemesRoot() {
    NSURL *support=[NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
    return [support URLByAppendingPathComponent:@"NyxianRecoveryThemes" isDirectory:YES];
}
@implementation NXTWRPThemeStore
+ (NSString *)activeDirectory {
    NSString *path=[NSUserDefaults.standardUserDefaults stringForKey:PathKey];
    NSString *root=ThemesRoot().path;
    if(![path hasPrefix:[root stringByAppendingString:@"/"]] || ![path isEqual:path.stringByStandardizingPath])return nil;
    return [NSFileManager.defaultManager fileExistsAtPath:[path stringByAppendingPathComponent:@"ui.xml"]]?path:nil;
}
+ (NSString *)activeName {return self.activeDirectory?([NSUserDefaults.standardUserDefaults stringForKey:NameKey]?:@"Imported theme"):@"Stock";}
+ (NSURL *)prepareArchive:(NSURL *)url error:(NSError **)error {
    if(error)*error=nil;
    NSFileManager *fm=NSFileManager.defaultManager;
    BOOL scoped=[url startAccessingSecurityScopedResource];
    NSURL *directory=[ThemesRoot() URLByAppendingPathComponent:NSUUID.UUID.UUIDString isDirectory:YES];
    struct archive *reader=nullptr;BOOL success=NO;NSString *reason=@"Invalid or damaged theme ZIP.";
    @try {
        NSNumber *size=nil;[url getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
        if(!size || size.unsignedLongLongValue>32*1024*1024){reason=@"Theme ZIP must be at most 32 MB.";return nil;}
        if(![fm createDirectoryAtURL:directory withIntermediateDirectories:YES attributes:nil error:error])return nil;
        reader=archive_read_new();if(!reader)return nil;
        archive_read_support_format_zip(reader);
        if(archive_read_open_filename(reader,url.fileSystemRepresentation,16384)!=0)return nil;
        NSMutableSet<NSString *> *paths=[NSMutableSet set];uint64_t total=0;NSUInteger count=0;
        archive_entry *entry=nullptr;int status;
        while((status=archive_read_next_header(reader,&entry))==0) {
            if(++count>4096){reason=@"Theme contains too many files.";return nil;}
            const char *raw=archive_entry_pathname(entry);NSString *name=raw?@(raw):nil;
            if(!name.length || [name hasPrefix:@"/"] || [name containsString:@"\\"] || [name.pathComponents containsObject:@".."] || [name.pathComponents containsObject:@"."]) {reason=@"Theme contains an unsafe file path.";return nil;}
            NSString *normalized=name.stringByStandardizingPath;
            if([paths containsObject:normalized]){reason=@"Theme contains duplicate file paths.";return nil;}[paths addObject:normalized];
            unsigned int type=archive_entry_filetype(entry);
            if(archive_entry_symlink(entry) || archive_entry_hardlink(entry) || (type!=S_IFREG && type!=S_IFDIR)){reason=@"Theme archives cannot contain links or special files.";return nil;}
            NSURL *target=[directory URLByAppendingPathComponent:normalized];
            if(![target.path hasPrefix:[directory.path stringByAppendingString:@"/"]])return nil;
            if(type==S_IFDIR){if(![fm createDirectoryAtURL:target withIntermediateDirectories:YES attributes:nil error:nil])return nil;continue;}
            int64_t declared=archive_entry_size(entry);
            if(declared<0 || declared>16*1024*1024){reason=@"A theme file exceeds the 16 MB limit.";return nil;}
            NSMutableData *data=[NSMutableData data];char buffer[16384];ssize_t n;
            while((n=archive_read_data(reader,buffer,sizeof(buffer)))>0) {
                total+=(uint64_t)n;
                if(total>64*1024*1024 || data.length+(NSUInteger)n>16*1024*1024){reason=@"Theme expands beyond the import size limit.";return nil;}
                [data appendBytes:buffer length:(NSUInteger)n];
            }
            if(n<0 || data.length!=(NSUInteger)declared)return nil;
            if(![fm createDirectoryAtURL:target.URLByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil] || ![data writeToURL:target options:NSDataWritingAtomic error:nil])return nil;
        }
        if(status!=1 || ![fm fileExistsAtPath:[directory URLByAppendingPathComponent:@"ui.xml"].path]) {reason=@"A TWRP theme must contain ui.xml at the ZIP root.";return nil;}
        success=YES;return directory;
    } @finally {
        if(reader)archive_read_free(reader);if(scoped)[url stopAccessingSecurityScopedResource];
        if(!success){[fm removeItemAtURL:directory error:nil];if(error && !*error)*error=ThemeError(reason);}
    }
}
+ (BOOL)activatePreparedTheme:(NSURL *)directory name:(NSString *)name error:(NSError **)error {
    NSAssert(NSThread.isMainThread,@"TWRP theme validation uses the main-thread renderer");
    if(![directory.path.stringByResolvingSymlinksInPath.stringByDeletingLastPathComponent isEqual:ThemesRoot().path.stringByResolvingSymlinksInPath]) {if(error)*error=ThemeError(@"Theme is outside the owned import directory.");return NO;}
    if(!NXTWRPValidateTheme(directory.path,error)) {
        [NSFileManager.defaultManager removeItemAtURL:directory error:nil];return NO;
    }
    [NSUserDefaults.standardUserDefaults setObject:directory.path forKey:PathKey];
    [NSUserDefaults.standardUserDefaults setObject:name forKey:NameKey];
    [NSNotificationCenter.defaultCenter postNotificationName:NXTWRPThemeDidChangeNotification object:nil];return YES;
}
+ (void)useStockTheme {
    [NSUserDefaults.standardUserDefaults removeObjectForKey:PathKey];
    [NSUserDefaults.standardUserDefaults removeObjectForKey:NameKey];
    dispatch_async(dispatch_get_main_queue(),^{[NSNotificationCenter.defaultCenter postNotificationName:NXTWRPThemeDidChangeNotification object:nil];});
}
@end
