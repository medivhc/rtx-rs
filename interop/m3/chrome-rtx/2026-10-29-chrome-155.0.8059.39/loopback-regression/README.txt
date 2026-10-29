R6-4 loopback regression after the authorized client-SETTINGS relaxation.

Command: cd interop/m3/rtx-server && ./run-loopback.sh (KEEP_WORK=1)
Result:  m3_b_loopback_matrix ... ok (1 passed; 0 failed), max_datagram_frame_size=1100.
Logs:    server.log + hashes.txt are the new run's staging copies.
Note:    run-loopback.sh writes its evidence to evidence/<date>-loopback; that
         merged directory was restored to its committed edca8ea content after
         this regression, so the new logs live only in this appendix.
The new server log line event=h3_client_qpack_capacity shows the relaxed branch
records 0/0 for the loopback client (it never advertises QPACK capacity).
