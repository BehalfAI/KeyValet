use super::*;
use std::os::fd::AsRawFd;

#[test]
fn invalid_kernel_credential_shapes_fail_closed() {
    for (pid, len) in [(0, 12), (-1, 12), (123, 0), (123, 11), (123, 13)] {
        let credentials = libc::ucred {
            pid,
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(
            validate_credentials(credentials, len).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn socket_identity_is_supplied_by_the_kernel() {
    let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    for fd in [a.as_raw_fd(), b.as_raw_fd()] {
        let c = peer_credentials(fd).unwrap();
        assert_eq!(c.uid, unsafe { libc::getuid() });
        assert_eq!(c.pid, std::process::id());
    }
    assert!(peer_credentials(-1).is_err());
}

#[test]
fn start_time_handles_spaces_and_parentheses_in_process_names() {
    let fields: Vec<_> = (3..=21).map(|n| n.to_string()).collect();
    let stat = format!("123 (a name (with) spaces)) {} 4567 23", fields.join(" "));
    assert_eq!(parse_start_time(&stat), Some(4567));
    assert!(process_start_time(std::process::id()).unwrap() > 0);
    assert_eq!(parse_start_time("broken"), None);
}

#[test]
fn tcp_lookup_ignores_server_and_non_loopback_and_rejects_ambiguous_users() {
    let row = |local, remote, uid| format!("0: {local} {remote} 01 0:0 00:0 0 {uid} 0 1");
    let client = row("0100007F:C001", "0100007F:1234", 1000);
    let server = row("0100007F:1234", "0100007F:C001", 123);
    let table = format!("header\n{server}\n{client}\n");
    assert_eq!(tcp_client_uid(&table, 0xC001), Some(1000));
    let other = row("0100007F:C001", "0100007F:5678", 1001);
    assert_eq!(tcp_client_uid(&format!("{table}{other}"), 0xC001), None);
    assert_eq!(
        tcp_client_uid(
            &format!("header\n{}", row("0100000A:C001", "0100007F:1234", 1000)),
            0xC001
        ),
        None
    );
}

#[test]
fn a_real_loopback_connection_reports_the_client_uid() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_server, _) = listener.accept().unwrap();
    assert_eq!(
        loopback_client(client.local_addr().unwrap().port()),
        Some(unsafe { libc::getuid() })
    );
}

#[test]
fn socket_identity_rejects_a_regular_file_and_reports_the_uid() {
    let file = tempfile::tempfile().unwrap();
    assert!(peer_credentials(file.as_raw_fd()).is_err());
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(peer_uid(a.as_raw_fd()).unwrap(), unsafe { libc::getuid() });
}

#[test]
fn process_identity_rejects_missing_and_malformed_start_times() {
    assert!(process_start_time(u32::MAX).is_err());
    for stat in ["", "1 (name)", "1 (name) S 1 2", "1 name S 1 2"] {
        assert_eq!(parse_start_time(stat), None);
    }
    let fields = (3..=21)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    for start in ["bad", "-1", "18446744073709551616"] {
        assert_eq!(
            parse_start_time(&format!("1 (name) {fields} {start}")),
            None
        );
    }
}

#[test]
fn tcp_lookup_rejects_malformed_matching_rows_and_ignores_inactive_connections() {
    for row in [
        "0: 0100007F 0100007F:1234 01 0:0 00:0 0 1000",
        "0: 0100007F:C001 0100007F 01 0:0 00:0 0 1000",
        "0: 0100007F:invalid 0100007F:1234 01 0:0 00:0 0 1000",
        "0: 0100007F:10000 0100007F:1234 01 0:0 00:0 0 1000",
        "0: 0100007F:C001 0100007F:1234 01 0:0 00:0 0 invalid",
        "0: 0100007F:C001 0100007F:1234 01 0:0 00:0 0 4294967296",
        "0: 0100007F:C001 0100007F:1234 0A 0:0 00:0 0 1000",
        "0: 0100007F:C001 0100007F:1234 06 0:0 00:0 0 1000",
        "0: 0100007F:C001 0100000A:1234 01 0:0 00:0 0 1000",
        "0: truncated",
    ] {
        assert_eq!(
            tcp_client_uid(&format!("header\n{row}"), 0xC001),
            None,
            "{row}"
        );
    }
    assert_eq!(tcp_client_uid("header\n", 0xC001), None);
}

#[test]
fn several_matching_tcp_connections_are_allowed_only_for_the_same_uid() {
    let table = "header\n0: 0100007F:C001 0100007F:1234 01 0:0 00:0 0 1000\n1: 0100007F:C001 0100007F:5678 01 0:0 00:0 0 1000\n";
    assert_eq!(tcp_client_uid(table, 0xC001), Some(1000));
    assert_eq!(tcp_client_uid(table, 0xC002), None);
}
