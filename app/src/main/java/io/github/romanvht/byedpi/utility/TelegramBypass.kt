package io.github.romanvht.byedpi.utility

/**
 * Raw MTProto (and "obfuscated2") traffic carries no TLS ClientHello or HTTP Host header,
 * so byedpi's SNI/Host-based desync groups (`-H`, `+s`, `+h`) never match it and it passes
 * through undesynced. Telegram's own IP ranges are stable and published officially, so this
 * group is scoped by IP set (`-j`) and port (`-V`) instead, which byedpi checks purely from
 * the destination address before any payload is parsed (see check_l34 in extend.c) - which is
 * enough to apply a blind split/disorder/fake offset to the first packet of any TCP connection
 * into these ranges, regardless of protocol content.
 *
 * Source: https://core.telegram.org/resources/cidr.txt (fetched 2026-09-24)
 */
object TelegramBypass {
    val cidrRanges = listOf(
        "91.108.56.0/22",
        "91.108.4.0/22",
        "91.108.8.0/22",
        "91.108.16.0/22",
        "91.108.12.0/22",
        "149.154.160.0/20",
        "91.105.192.0/23",
        "91.108.20.0/22",
        "185.76.151.0/24",
        "2001:b28:f23d::/48",
        "2001:b28:f23f::/48",
        "2001:67c:4e8::/48",
        "2001:b28:f23c::/48",
        "2a0a:f280::/32",
    )

    // -V/--pf takes a single port or one contiguous range, not a comma list, so each port
    // needs its own desync group (all sharing the same ipset).
    val ports = listOf("443", "80", "5222")
}
