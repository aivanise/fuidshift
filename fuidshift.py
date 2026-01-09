#!/usr/bin/env python3
import os
import sys
import stat
import struct

"""
LXD-equivalent UID/GID shifter with full metadata preservation.
Mimics LXD's internal logic for remapping container filesystems.
"""

# POSIX ACL constants
ACL_EA_VERSION = 2
ACL_TAG_USER = 0x02
ACL_TAG_GROUP = 0x08
ACL_ENTRY_SIZE = 8
ACL_HEADER_SIZE = 4
ACL_HEADER_FORMAT = '<I'
ACL_ENTRY_FORMAT = '<HHI'

DEBUG = 'DEBUG' in os.environ

def shift_id(current_id, offset):
    """Apply offset logic: shift up if offset > 0, down if offset < 0."""
    abs_offset = abs(offset)
    if offset > 0:
        if current_id < abs_offset:
            return current_id + offset
    else:
        if current_id >= abs_offset:
            return current_id + offset
    return current_id

def modify_acl_blob(blob, offset):
    """Parse POSIX ACL blob, shift user/group IDs, return modified blob."""
    try:
        if len(blob) < ACL_HEADER_SIZE:
            return blob
        
        (version,) = struct.unpack(ACL_HEADER_FORMAT, blob[:ACL_HEADER_SIZE])
        if version != ACL_EA_VERSION:
            return blob
        
        if (len(blob) - ACL_HEADER_SIZE) % ACL_ENTRY_SIZE != 0:
            return blob

        new_blob = bytearray(blob[:ACL_HEADER_SIZE])
        num_entries = (len(blob) - ACL_HEADER_SIZE) // ACL_ENTRY_SIZE
        
        for i in range(num_entries):
            entry_offset = ACL_HEADER_SIZE + (i * ACL_ENTRY_SIZE)
            tag, perm, old_id = struct.unpack_from(ACL_ENTRY_FORMAT, blob, entry_offset)
            
            new_id = old_id
            if tag in (ACL_TAG_USER, ACL_TAG_GROUP):
                new_id = shift_id(old_id, offset)
            
            new_blob.extend(struct.pack(ACL_ENTRY_FORMAT, tag, perm, new_id))
        
        return bytes(new_blob)
    except struct.error:
        return blob

def shift_file(path, offset):
    """
    LXD-equivalent shifter: performs intelligent remapping while preserving metadata.
    """
    try:
        # Step 1: Read full metadata using lstat (don't follow symlinks)
        stat_info = os.lstat(path)
        old_uid = stat_info.st_uid
        old_gid = stat_info.st_gid
        old_mode = stat_info.st_mode
        is_symlink = stat.S_ISLNK(old_mode)
        
        # Calculate new UID/GID
        new_uid = shift_id(old_uid, offset)
        new_gid = shift_id(old_gid, offset)
        
        # If no ownership change, skip
        if new_uid == old_uid and new_gid == old_gid:
            return
        
        # Step 2: Read all extended attributes BEFORE chown
        xattrs_backup = {}
        acl_xattrs = {
            'system.posix_acl_access',
            'system.posix_acl_default'
        }
        try:
            for name in os.listxattr(path, follow_symlinks=False):
                try:
                    value = os.getxattr(path, name, follow_symlinks=False)
                    # If it's an ACL, we'll shift it; otherwise preserve as-is
                    if name in acl_xattrs:
                        xattrs_backup[name] = modify_acl_blob(value, offset)
                    else:
                        xattrs_backup[name] = value
                except OSError:
                    pass
        except OSError:
            pass  # Filesystem might not support xattrs
        
        # Step 3: Perform ownership change (lchown)
        # This is where the kernel clears SUID/SGID and capabilities
        os.lchown(path, new_uid, new_gid)
        
        # Step 4: Restore metadata (the "smart" part that LXD does)
        
        # 4a. Restore mode bits (SUID/SGID/sticky) if not a symlink
        if not is_symlink:
            try:
                os.chmod(path, stat.S_IMODE(old_mode))
            except OSError as e:
                print(f"Warning: Could not restore mode on {path}: {e}", file=sys.stderr)
        
        # 4b. Restore extended attributes (including capabilities, ACLs, SELinux labels)
        for name, value in xattrs_backup.items():
            try:
                os.setxattr(path, name, value, follow_symlinks=False)
            except OSError as e:
                print(f"Warning: Could not restore xattr '{name}' on {path}: {e}", file=sys.stderr)
        
        # Print progress only if DEBUG
        if DEBUG:
            mode_str = stat.filemode(old_mode)
            print(f"Shifted: {path} ({old_uid}:{old_gid} -> {new_uid}:{new_gid}) {mode_str}")

    except (OSError, PermissionError) as e:
        print(f"Error processing {path}: {e}", file=sys.stderr)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: [export DEBUG=yes]; {sys.argv[0]} <directory> <offset>")
        print(f"  Example (LXD shift down): sudo {sys.argv[0]} /var/lib/lxd/containers/mycontainer/rootfs -1000000")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    try:
        offset = int(sys.argv[2])
    except ValueError:
        print(f"Error: offset must be an integer", file=sys.stderr)
        sys.exit(1)
    
    if offset == 0:
        print("Error: offset cannot be zero", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.isdir(target_dir):
        print(f"Error: Directory not found: {target_dir}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Starting LXD-equivalent shift in {target_dir}")
    print(f"Offset: {offset:+d}")
    print("---")
    
    # Walk the tree bottom-up (so directories are processed after their contents)
    for root, dirs, files in os.walk(target_dir, topdown=False):
        for fname in files:
            shift_file(os.path.join(root, fname), offset)
        
        for dname in dirs:
            dpath = os.path.join(root, dname)
            # Only process symlinks to directories here; real dirs will be processed as 'root'
            if os.path.islink(dpath):
                shift_file(dpath, offset)
        
        # Process the directory itself last
        shift_file(root, offset)
    
    print("---")
    print("Shift complete.")

if __name__ == "__main__":
    main()

