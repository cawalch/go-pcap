"""Check the DoQ fixture names with an independent loopback DNS client."""

import asyncio
import struct
import sys

import dns.asyncquery
import dns.message
import dns.rrset
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration

ANSWERS = {"one.example.": "192.0.2.10", "two.example.": "192.0.2.11"}


async def resolver(reader, writer):
    size = struct.unpack("!H", await reader.readexactly(2))[0]
    query = dns.message.from_wire(await reader.readexactly(size))
    assert query.id == 0 and len(query.question) == 1
    assert await reader.read() == b""
    name = query.question[0].name.to_text()
    reply = dns.message.make_response(query)
    reply.answer.append(dns.rrset.from_text(name, 30, "IN", "A", ANSWERS[name]))
    wire = reply.to_wire()
    writer.write(struct.pack("!H", len(wire)) + wire)
    writer.write_eof()


async def main():
    config = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    config.load_cert_chain(sys.argv[1], sys.argv[2])
    server = await serve(
        "127.0.0.1", 0, configuration=config,
        stream_handler=lambda reader, writer: asyncio.create_task(resolver(reader, writer)),
    )
    try:
        port = server._transport.get_extra_info("sockname")[1]
        for name, address in ANSWERS.items():
            query = dns.message.make_query(name, "A")
            reply = await dns.asyncquery.quic(query, "127.0.0.1", port=port, timeout=2, verify=False)
            assert reply.answer[0][0].address == address
            print(f"{name} {address}")
    finally:
        server.close()


if __name__ == "__main__":
    asyncio.run(main())
