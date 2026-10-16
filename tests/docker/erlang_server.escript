#!/usr/bin/env escript
%% A throwaway Erlang/OTP ssh server for CI: another independent SSH implementation, known for following the RFCs strictly (#218).
%%
%% It runs as the test account and serves the transport, password authentication, SFTP (ssh_sftpd, from the home directory) and TCP
%% forwarding in both directions. Shells and commands are turned off: Erlang's run Erlang expressions, and an OS process through an
%% Erlang port cannot keep stderr apart or close only its stdin, so the session tests would test the server's shortcuts instead. The
%% account's password comes from TEST_PASSWORD, the host keys from the directory in HOSTKEY_DIR. Never used outside CI.

main(_) ->
    Password = os:getenv("TEST_PASSWORD"),
    Port = list_to_integer(os:getenv("PORT", "2222")),
    {ok, Home} = file:get_cwd(),
    ok = ssh:start(),
    {ok, _} = ssh:daemon(Port, [
        {system_dir, os:getenv("HOSTKEY_DIR")},
        {user_passwords, [{"sshsharp", Password}]},
        {subsystems, [ssh_sftpd:subsystem_spec([{cwd, Home}])]},
        {shell, disabled},
        {exec, disabled},
        {tcpip_tunnel_in, true},
        {tcpip_tunnel_out, true}
    ]),
    {ok, Version} = application:get_key(ssh, vsn),
    io:format(standard_error, "Erlang/OTP ~s ssh ~s listening on port ~p~n", [erlang:system_info(otp_release), Version, Port]),
    receive stop -> ok end.
