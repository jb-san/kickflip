/**
 * This module is responsible for ssh related operations
 */

pub fn is_sshd_installed() -> bool {
    let output = Command::new("ssh").arg("-V").output().unwrap();
    output.status.success()
}
