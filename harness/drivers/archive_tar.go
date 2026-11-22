// Reads a tar archive with Go's archive/tar and prints each member.
//
// Usage: archive-tar ARCHIVE
//
// One line per header Next returns, global headers included, its fields
// separated by tabs and every text field in hexadecimal: "member", the
// typeflag, the path, the link target, the size, the device's major and
// minor numbers, the mode in decimal, the modification time in whole seconds
// (floored), the uid, the gid, the owner's name, the group's name, and the
// data read through the reader. Then "ok", or "error" and the error, in
// hexadecimal.
package main

import (
	"archive/tar"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	var out strings.Builder
	defer func() { os.Stdout.WriteString(out.String()) }()
	fail := func(err error) {
		fmt.Fprintf(&out, "error\t%s\n", hex.EncodeToString([]byte(err.Error())))
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		fail(err)
		return
	}
	defer file.Close()
	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			out.WriteString("ok\n")
			return
		}
		if err != nil {
			fail(err)
			return
		}
		typeflag := header.Typeflag
		data, readErr := io.ReadAll(reader)
		fmt.Fprintf(&out, "member\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n",
			hex.EncodeToString([]byte{typeflag}),
			hex.EncodeToString([]byte(header.Name)),
			hex.EncodeToString([]byte(header.Linkname)),
			header.Size,
			header.Devmajor,
			header.Devminor,
			header.Mode,
			header.ModTime.Unix(),
			header.Uid,
			header.Gid,
			hex.EncodeToString([]byte(header.Uname)),
			hex.EncodeToString([]byte(header.Gname)),
			hex.EncodeToString(data))
		if readErr != nil {
			fail(readErr)
			return
		}
	}
}
