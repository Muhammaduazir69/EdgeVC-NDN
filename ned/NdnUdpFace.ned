package ned;

simple NdnUdpFace
{
    parameters:
        @display("i=block/socket");
        int localPort;
        string remotes = default("");    // "host:port host:port" for the first faces
    gates:
        input socketIn;
        output socketOut;
        inout ndn[];
}
