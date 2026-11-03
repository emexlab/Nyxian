/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Licensed under the emexLabs Public Source License, version 1.1
 (EPSL 1.1).

 Private use and modification are permitted under the license.
 Redistribution of source or binaries, modified or unmodified,
 requires prior written permission from emexLabs.

 External deployment is subject to the source-availability
 requirements and other conditions of the license.

 Provided "AS IS", without warranty, to the extent permitted by law.

 See LICENSE for the full license terms.
*/

#import <LindChain/Utils/Zip.h>

#ifndef MY_LIBARCHIVE_H
#define MY_LIBARCHIVE_H

#include <unistd.h>
#include <stddef.h>

typedef int64_t la_int64_t;
typedef struct archive archive;
typedef struct archive_entry archive_entry;

struct archive {};
struct archive_entry {};

// Flags
#define ARCHIVE_EXTRACT_TIME    1
#define ARCHIVE_EXTRACT_PERM    2
#define ARCHIVE_EXTRACT_ACL     4
#define ARCHIVE_EXTRACT_FFLAGS  8

#define ARCHIVE_OK  0
#define ARCHIVE_EOF 1

// Reader functions
archive* archive_read_new(void);
int archive_read_open_fd(struct archive *a, int fd, size_t block_size);
int archive_read_support_format_all(archive *a);
int archive_read_support_filter_all(archive *a);
int archive_read_open_filename(archive *a, const char *filename, size_t block_size);
int archive_read_next_header(archive *a, archive_entry **entry);
int archive_read_data_block(archive *a, const void **buff, size_t *size, long long *offset);
int archive_read_close(archive *a);
int archive_read_free(archive *a);
int archive_write_finish_entry(struct archive *);

// Writer functions
archive* archive_write_disk_new(void);
int archive_write_open_filename(struct archive *a, const char *filename);
ssize_t archive_write_data(struct archive *a, const void *buff, size_t size);
int archive_write_disk_set_options(archive *a, int flags);
int archive_write_header(archive *a, archive_entry *entry);
int archive_write_data_block(archive *a, const void *buff, size_t size, long long offset);
int archive_write_close(archive *a);
int archive_write_free(archive *a);
archive* archive_write_new(void);
int archive_write_set_format_zip(struct archive *a);

// Entry functions
const char* archive_entry_pathname(archive_entry *entry);
void archive_entry_set_pathname(archive_entry *entry, const char *pathname);
void archive_entry_set_size(struct archive_entry *entry, la_int64_t size);
void archive_entry_set_filetype(struct archive_entry *entry, unsigned int filetype);
void archive_entry_set_perm(struct archive_entry *entry, int perm);
void archive_entry_free(struct archive_entry *entry);
struct archive_entry *archive_entry_new(void);

// Error functions
const char* archive_error_string(archive *a);

#ifndef AE_IFREG
#define AE_IFREG 0100000  // regular file
#endif
#ifndef AE_IFDIR
#define AE_IFDIR 0040000  // directory
#endif

#endif // MY_LIBARCHIVE_H

BOOL unzipArchiveAtPath(NSString *zipPath, NSString *destinationPath) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int r;

    a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);

    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);

    if ((r = archive_read_open_filename(a, [zipPath fileSystemRepresentation], 10240))) {
        NSLog(@"archive_read_open_filename() failed: %s", archive_error_string(a));
        archive_read_free(a);
        archive_write_free(ext);
        return NO;
    }

    while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        NSString *fullPath = [destinationPath stringByAppendingPathComponent:
                              [NSString stringWithUTF8String:archive_entry_pathname(entry)]];
        archive_entry_set_pathname(entry, [fullPath fileSystemRepresentation]);
        archive_entry_set_perm(entry, 0777);
        r = archive_write_header(ext, entry);
        if (r == ARCHIVE_OK) {
            const void *buff;
            size_t size;
            la_int64_t offset;
            while (archive_read_data_block(a, &buff, &size, &offset) == ARCHIVE_OK) {
                archive_write_data_block(ext, buff, size, offset);
            }
        }
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    return YES;
}

BOOL unzipArchiveAtPathWithoutParentDirectory(NSString *zipPath,
                                              NSString *destinationPath)
{
    return unzipArchiveAtPathWithoutParentDirectoryWithError(zipPath, destinationPath, NULL);
}

static void NXZipReportExtractionError(NSError **error,
                                       struct archive *archive,
                                       NSString *operation,
                                       NSString *path)
{
    if(!error || *error)
    {
        return;
    }
    
    const char *detail = archive_error_string(archive);
    NSString *reason = detail ? [NSString stringWithUTF8String:detail] : @"libarchive returned no error description";
    *error = [NSError errorWithDomain:@"org.emexlabs.nyxian.zip" code:1 userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"ZIP extraction failed while %@ (%@): %@", operation, path, reason]}];
}

BOOL unzipArchiveAtPathWithoutParentDirectoryWithError(NSString *zipPath,
                                                       NSString *destinationPath,
                                                       NSError **error)
{
    if(error)
    {
        *error = nil;
    }
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    struct archive_entry *entry;
    int r;
    
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);
    r = archive_read_open_filename(a, [zipPath fileSystemRepresentation], 10240);
    if(r != ARCHIVE_OK)
    {
        NSLog(@"archive_read_open_filename() failed: %s", archive_error_string(a));
        NXZipReportExtractionError(error, a, @"opening the archive", zipPath);
        archive_read_free(a);
        archive_write_free(ext);
        return NO;
    }
    
    BOOL success = YES;
    
    while((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK)
    {
        const char *entryPath = archive_entry_pathname(entry);
        if(!entryPath)
        {
            continue;
        }
        
        NSString *relativePath = [NSString stringWithUTF8String:entryPath];
        NSArray<NSString *> *components = [relativePath pathComponents];
        
        if(components.count <= 1)
        {
            continue;
        }
        
        NSArray<NSString *> *remainingComponents = [components subarrayWithRange:NSMakeRange(1, components.count - 1)];
        
        BOOL unsafe = !relativePath || relativePath.isAbsolutePath || [components containsObject:@".."];
        NSString *strippedPath = [NSString pathWithComponents:remainingComponents];
        NSString *fullPath = [destinationPath stringByAppendingPathComponent:strippedPath];
        
        if(unsafe)
        {
            NSLog(@"Skipping unsafe archive path: %@", relativePath);
            if(error && !*error)
            {
                *error = [NSError errorWithDomain:@"org.emexlabs.nyxian.zip" code:2 userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Unsafe ZIP entry: %@", relativePath]}];
            }
            success = NO;
            continue;
        }
        
        archive_entry_set_pathname(entry, [fullPath fileSystemRepresentation]);
        archive_entry_set_perm(entry, 0777);
        
        r = archive_write_header(ext, entry);
        
        if(r < ARCHIVE_OK)
        {
            NSLog(@"archive_write_header() warning: %s", archive_error_string(ext));
        }
        
        if(r == ARCHIVE_OK)
        {
            const void *buff;
            size_t size;
            la_int64_t offset;
            while((r = archive_read_data_block(a, &buff, &size, &offset)) == ARCHIVE_OK)
            {
                int writeResult = archive_write_data_block(ext, buff, size, offset);
                if(writeResult != ARCHIVE_OK)
                {
                    NSLog(@"archive_write_data_block() failed: %s", archive_error_string(ext));
                    NXZipReportExtractionError(error, ext, @"writing entry data", fullPath);
                    success = NO;
                    break;
                }
            }
            
            if(r != ARCHIVE_EOF && r != ARCHIVE_OK)
            {
                NSLog(@"archive_read_data_block() failed: %s", archive_error_string(a));
                NXZipReportExtractionError(error, a, @"reading entry data", relativePath);
                success = NO;
            }
        }
        
        archive_write_finish_entry(ext);
    }
    
    if(r != ARCHIVE_EOF)
    {
        NSLog(@"archive_read_next_header() failed: %s", archive_error_string(a));
        NXZipReportExtractionError(error, a, @"reading the next entry", zipPath);
        success = NO;
    }
    
    archive_read_close(a);
    archive_read_free(a);
    
    archive_write_close(ext);
    archive_write_free(ext);
    
    return success;
}

BOOL unzipArchiveFromFileDescriptor(int fd,
                                    NSString *destinationPath)
{
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int r;
    
    a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS);
    
    if((r = archive_read_open_fd(a, fd, 10240)))
    {
        NSLog(@"archive_read_open_fd() failed: %s", archive_error_string(a));
        archive_read_free(a);
        archive_write_free(ext);
        return NO;
    }
    
    while((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK)
    {
        NSString *fullPath = [destinationPath stringByAppendingPathComponent:[NSString stringWithUTF8String:archive_entry_pathname(entry)]];
        archive_entry_set_pathname(entry, [fullPath fileSystemRepresentation]);
        archive_entry_set_perm(entry, 0777);
        r = archive_write_header(ext, entry);
        if(r == ARCHIVE_OK)
        {
            const void *buff;
            size_t size;
            la_int64_t offset;
            while(archive_read_data_block(a, &buff, &size, &offset) == ARCHIVE_OK)
            {
                archive_write_data_block(ext, buff, size, offset);
            }
        }
    }
    
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    return YES;
}

BOOL unzipArchiveFromFileHandle(NSFileHandle *zipFileHandle, NSString *destinationPath) {
    return unzipArchiveFromFileDescriptor(zipFileHandle.fileDescriptor, destinationPath);
}

BOOL zipDirectoryAtPath(NSString *directoryPath, NSString *zipPath, BOOL keepParent) {
    struct archive *a;
    struct archive_entry *entry;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSDirectoryEnumerator *enumerator;
    NSString *filePath;

    // Determine base path for archive entries
    NSString *basePath = keepParent ? [directoryPath stringByDeletingLastPathComponent] : directoryPath;

    // Create new archive for writing
    a = archive_write_new();
    archive_write_set_format_zip(a); // Set format to ZIP

    // Open archive for writing to filename
    if (archive_write_open_filename(a, [zipPath fileSystemRepresentation]) != ARCHIVE_OK) {
        NSLog(@"Failed to create archive: %s", archive_error_string(a));
        archive_write_free(a);
        return NO;
    }

    // Enumerate all files
    enumerator = [fileManager enumeratorAtPath:directoryPath];
    while ((filePath = [enumerator nextObject])) {
        NSString *fullPath = [directoryPath stringByAppendingPathComponent:filePath];
        BOOL isDir;
        if ([fileManager fileExistsAtPath:fullPath isDirectory:&isDir]) {
            entry = archive_entry_new();

            // Determine the path inside the archive
            NSString *relativePath = [fullPath stringByReplacingOccurrencesOfString:basePath
                                                                       withString:@""];
            // Remove leading slash if any
            if ([relativePath hasPrefix:@"/"] || [relativePath hasPrefix:@"."]) {
                relativePath = [relativePath substringFromIndex:1];
            }

            archive_entry_set_pathname(entry, [relativePath UTF8String]);

            NSDictionary *attributes = [fileManager attributesOfItemAtPath:fullPath error:nil];
            archive_entry_set_size(entry, isDir ? 0 : [attributes[NSFileSize] longLongValue]);
            archive_entry_set_filetype(entry, isDir ? AE_IFDIR : AE_IFREG);
            archive_entry_set_perm(entry, [attributes[NSFilePosixPermissions] intValue]);

            // Write header
            if (archive_write_header(a, entry) == ARCHIVE_OK && !isDir) {
                NSData *data = [NSData dataWithContentsOfFile:fullPath];
                archive_write_data(a, [data bytes], [data length]);
            }

            archive_entry_free(entry);
        }
    }

    archive_write_close(a);
    archive_write_free(a);
    return YES;
}
