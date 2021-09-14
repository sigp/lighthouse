use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
#[cfg(windows)]
use winapi::um::winnt::{FILE_GENERIC_READ, FILE_GENERIC_WRITE, STANDARD_RIGHTS_ALL};

/// This is the security identifier in Windows for the owner of a file. See:
/// - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows#well-known-sids-all-versions-of-windows
#[cfg(windows)]
const OWNER_SID_STR: &str = "S-1-3-4";
/// We don't need any of the `AceFlags` listed here:
/// - https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header
#[cfg(windows)]
const OWNER_ACL_ENTRY_FLAGS: u8 = 0;
/// Generic Rights:
///  - https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
/// Individual Read/Write/Execute Permissions (referenced in generic rights link):
///  - https://docs.microsoft.com/en-us/windows/win32/wmisdk/file-and-directory-access-rights-constants
/// STANDARD_RIGHTS_ALL
///  - https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
#[cfg(windows)]
const OWNER_ACL_ENTRY_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | STANDARD_RIGHTS_ALL;

#[derive(Debug)]
pub enum Error {
    /// The file could not be created
    UnableToCreateFile(io::Error),
    /// The file could not be copied
    UnableToCopyFile(io::Error),
    /// The file could not be opened
    UnableToOpenFile(io::Error),
    /// The file could not be renamed
    UnableToRenameFile(io::Error),
    /// Failed to set permissions
    UnableToSetPermissions(io::Error),
    /// Failed to retrieve file metadata
    UnableToRetrieveMetadata(io::Error),
    /// Failed to write bytes to file
    UnableToWriteFile(io::Error),
    /// Failed to obtain file path
    UnableToObtainFilePath,
    /// Failed to convert string to SID
    UnableToConvertSID(u32),
    /// Failed to retrieve ACL for file
    UnableToRetrieveACL(u32),
    /// Failed to enumerate ACL entries
    UnableToEnumerateACLEntries(u32),
    /// Failed to add new ACL entry
    UnableToAddACLEntry(String),
    /// Failed to remove ACL entry
    UnableToRemoveACLEntry(String),
}

/// Creates a file with `600 (-rw-------)` permissions and writes the specified bytes to file.
pub fn create_with_600_perms<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), Error> {
    let path = path.as_ref();
    let mut file = File::create(&path).map_err(Error::UnableToCreateFile)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = file
            .metadata()
            .map_err(Error::UnableToRetrieveMetadata)?
            .permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)
            .map_err(Error::UnableToSetPermissions)?;
    }

    file.write_all(bytes).map_err(Error::UnableToWriteFile)?;
    #[cfg(windows)]
    {
        restrict_file_permissions(path)?;
    }

    Ok(())
}

pub fn restrict_file_permissions<P: AsRef<Path>>(path: P) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = File::open(path.as_ref()).map_err(Error::UnableToOpenFile)?;
        let mut perm = file
            .metadata()
            .map_err(Error::UnableToRetrieveMetadata)?
            .permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)
            .map_err(Error::UnableToSetPermissions)?;
    }

    #[cfg(windows)]
    {
        use winapi::um::winnt::PSID;
        use windows_acl::acl::{AceType, ACL};
        use windows_acl::helper::sid_to_string;

        let path_str = path
            .as_ref()
            .to_str()
            .ok_or(Error::UnableToObtainFilePath)?;
        let mut acl = ACL::from_file_path(&path_str, false).map_err(Error::UnableToRetrieveACL)?;

        let owner_sid =
            windows_acl::helper::string_to_sid(OWNER_SID_STR).map_err(Error::UnableToConvertSID)?;

        let entries = acl.all().map_err(Error::UnableToEnumerateACLEntries)?;

        // add single entry for file owner
        acl.add_entry(
            owner_sid.as_ptr() as PSID,
            AceType::AccessAllow,
            OWNER_ACL_ENTRY_FLAGS,
            OWNER_ACL_ENTRY_MASK,
        )
        .map_err(|code| {
            Error::UnableToAddACLEntry(format!(
                "Failed to add ACL entry for SID {} error={}",
                OWNER_SID_STR, code
            ))
        })?;
        // remove all AccessAllow entries from the file that aren't the owner_sid
        for entry in &entries {
            if let Some(ref entry_sid) = entry.sid {
                let entry_sid_str = sid_to_string(entry_sid.as_ptr() as PSID)
                    .unwrap_or_else(|_| "BadFormat".to_string());
                if entry_sid_str != OWNER_SID_STR {
                    acl.remove(entry_sid.as_ptr() as PSID, Some(AceType::AccessAllow), None)
                        .map_err(|_| {
                            Error::UnableToRemoveACLEntry(format!(
                                "Failed to remove ACL entry for SID {}",
                                entry_sid_str
                            ))
                        })?;
                }
            }
        }
    }

    Ok(())
}
