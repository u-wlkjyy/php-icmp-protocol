<?php
const PROTOCOL = 'icmp';

/**
 * @throws Exception
 */
function ping($address, $count=4): array
{
    $ipAddress = gethostbyname($address);
    if($ipAddress === $address and ! filter_var($address, FILTER_VALIDATE_IP)){
        throw new Exception('cannot resolve ' . $address . ': Unknown host');
    }
    $protocolNumber = getprotobyname(PROTOCOL);
    $socket         = socket_create(AF_INET, SOCK_RAW, $protocolNumber);
    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec' => 1, 'usec' => 0));
    socket_connect($socket, $ipAddress, 0);
    $hostIsAlive = false;
    $result = [];

    for ($i = 0; $i < $count; $i++) {
        $startTime = microtime(true);

        $package  = "\x08\x00\x19\x2f\x00\x00\x00\x00\x70\x69\x6e\x67";
        socket_send($socket, $package, strlen($package), 0);


        if (socket_read($socket, 255)) {
            $hostIsAlive = true;
            $result[] = [
                'ip' => $ipAddress,
                'bytes' => 32,
                'ttl' => sprintf('%.3f', round((microtime(true) - $startTime) * 1000, 3))
            ];
        } else {
            $result[] = [
                'ip' => $ipAddress,
                'bytes' => 32,
                'ttl' => -1,
            ];
        }
    }
    socket_close($socket);
    return $result;
}

print_r(ping('www.007idc.cn', 4, true));