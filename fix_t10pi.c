/*

fix_t10pi.c

Copyright 2020, Brigham Young University
Author: Ryan Cox <ryan_cox@byu.edu>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


DESCRIPTION:
This program is designed to work with T10-PI Type 2 checksums (and maybe Type 1 and Type 3???) with one interval appended to each sector. It overwrites each byte of the entire 8 byte checksum with 0xff in *each sector* which, according to the standard, disables integrity checking for that sector (see https://oss.oracle.com/projects/data-integrity/dist/documentation/dix.pdf). Depending on the type, it may be sufficient to overwrite only the 2 byte application tag. This is the case for Type 2 but it doesn't hurt to overwrite the whole 8 bytes. THIS PROGRAM WAS ONLY TESTED ON TYPE 2 IN ONE SPECIFIC ENVIRONMENT. YMMV.

If this program was helpful to you, please send me an email at ryan_cox@byu.edu to let me know. I'm just curious :)


WARNING:
Exercise caution when using random code you find on the internet, especially this code. This software will probably irretrievably corrupt all of your data, including backups. Your data center may catch on fire. Seriously, be careful. Make many clones first. Operate only on clones of the drives attached to computers that contain nothing of value. This program was run successfully once on a set of source and target drives with T10-PI Type 2 in one environment but no attempt has been made since then to make this code nice and portable. There has been no QA. Don't accidentally delete your data.


USAGE:
usage: programname <source path with T10-PI> <destination path with T10-PI> [optonal destination path that receives ONLY user data without any T10-PI, probably a pipe to a checksum program]

You can use /dev/stdin and /dev/stdout as paths.

ddpt can be used to copy data around: `ddpt ... --protect=3` for reading data in with T10-PI information and `ddpt ... --protect=0,3` for writing data out with T10-PI information. It will write out a file with the T10-PI checksums interleaved with the data (meaning every 4096 data bytes from the disk becomes 4104 bytes in the output since it includes the checksum or 520 for 512 byte sectors). The second example can take that file with the interleaved checksums and write it back out to a disk.

You can clone directly from one drive to another AND generate a checksum of the user data (checksum bytes omitted) using something like this: ddpt if=/dev/sde of=- status=progress iflag=pt bs=4096 --protect=3 | ./fix_t10pi /dev/stdin /dev/stout >(sha256sum - > somefile.sha256sum) | ddpt if=- of=/dev/sdr oflag=pt bs=4096 --protect=0,3
You can also use ddpt to read and write files that contain T10-PI checksums appended to each sector, rather than directly reading or writing from disks. Note that this program has a "configurable" sector size. Change the #define SECTOR_SIZE_DATA_ONLY to 512 then recompile (if that's your sector size). I could have made that an optional program argument, but why bother? :)

If you are using Type 2, you will likely need to add cdbsz=32 to each invocation of ddpt.


USEFUL REFERENCES:
* lots of tools from the sg3_utils package (That's the Debian name for it. Not sure of RHEL, etc)
* sg_readcap --long /dev/sg0 # or whatever device it is
* man sg_format
* Documents such as dix.pdf at https://oss.oracle.com/projects/data-integrity/documentation/ 
* http://sg.danny.cz/sg/scsi_debug.html (you can set up your own fake SCSI device for testing)
* http://sg.danny.cz/sg/ddpt.html
* https://www.kernel.org/doc/html/latest/block/data-integrity.html
* https://www.t10.org/ftp/t10/document.03/03-224r0.pdf
* https://www.ibm.com/support/knowledgecenter/linuxonibm/liaau/t10pi.html
* https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100293068j.pdf (SCSI Commands Reference Manual. Especially the section on RDPROTECT which states that 011b (decimal 3) is the value you need to set to ignore checksums.)

If you're reading this document, I am sorry. I don't think there's a "good" reason to be here, only sad reasons (unless you work at a data recovery company who makes money doing this).

*/

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#define SECTOR_SIZE_DATA_ONLY 4096
#define SECTOR_SIZE_WITH_T10PI (SECTOR_SIZE_DATA_ONLY + 8)

int main(int argc, char **argv) {
	int infile = -1, outfile = -1, outfile2 = -1, rc = 1, outfile2_broken = -1;
	ssize_t read_bytes, wrote_bytes, wrote_bytes2;
	uint64_t sector_count = 0, bytes_count = 0, bytes_count_nopi = 0;
	char buf[SECTOR_SIZE_WITH_T10PI];

	if (argc != 3 && argc != 4) {
		fprintf(stderr, "usage: ./programname <source path> <destination path> [second destination path which will only receive the data, not checksums]\n");
		return rc;
	}

	infile = open(argv[1], O_RDONLY | O_LARGEFILE);
	if (infile < 0) {
		fprintf(stderr, "opening \"%s\" for reading: %m\n", argv[1]);
		return rc;
	}

	outfile = open(argv[2], O_WRONLY | O_LARGEFILE | O_CREAT, 0600);
	if (outfile < 0) {
		fprintf(stderr, "opening \"%s\" for writing: %m\n", argv[2]);
		return rc;
	}

	if (argc == 4) {
		outfile2 = open(argv[3], O_WRONLY | O_LARGEFILE | O_CREAT, 0600);
		if (outfile2 < 0) {
			fprintf(stderr, "opening \"%s\" for writing: %m\n", argv[3]);
		} else {
			outfile2_broken = 0;
		}
	}

	fprintf(stderr, "Copying from \"%s\" to \"%s\" and overwriting the application tag. Assuming %d byte sector size with one interval of 8 bytes T10-PI Type 2.\n", argv[1], argv[2], SECTOR_SIZE_DATA_ONLY);
	while ( (read_bytes = read(infile, buf, SECTOR_SIZE_WITH_T10PI)) > 0) {
		if (read_bytes != SECTOR_SIZE_WITH_T10PI) {
			fprintf(stderr, "error: expected %d bytes but read %d.\n", SECTOR_SIZE_WITH_T10PI, read_bytes);
			goto theend;
		}

		/* copy raw data WITH NO CHECKSUMS to outfile2 if needed */
		if (argc == 4 && outfile2_broken == 0) {
			wrote_bytes2 = write(outfile2, buf, SECTOR_SIZE_DATA_ONLY);
			if (wrote_bytes2 != SECTOR_SIZE_DATA_ONLY) {
				fprintf(stderr, "error: attempted to write %d bytes to second destination but only wrote %d: %m\n", SECTOR_SIZE_DATA_ONLY, wrote_bytes2);
				outfile2_broken = 1;
			}
		}

		/* Overwrite each byte of the entire checksum with 0xff. Might as well. (Application tag is at SECTOR_SIZE_WITH_T10PI-6 and SECTOR_SIZE_WITH_T10PI-5) */
		for (int i = SECTOR_SIZE_WITH_T10PI - 8; i < SECTOR_SIZE_WITH_T10PI; i++) {
			buf[i] = 0xff;
		}

		/* write modified buffer to outfile */
		wrote_bytes = write(outfile, buf, SECTOR_SIZE_WITH_T10PI);
		if (wrote_bytes != SECTOR_SIZE_WITH_T10PI) {
			fprintf(stderr, "error: attempted to write %d bytes but only wrote %d: %m\n", SECTOR_SIZE_WITH_T10PI, wrote_bytes);
			goto theend;
		}

		sector_count++;
		bytes_count += SECTOR_SIZE_WITH_T10PI;
		bytes_count_nopi += SECTOR_SIZE_DATA_ONLY;

		/* print periodic updates */
		if (sector_count % 1953125 == 0) {
			fprintf(stderr, "Copied %"PRIu64" sectors, %"PRIu64" data bytes (%"PRIu64" GB (1e+9 bytes)), %"PRIu64" data bytes + T10-PI checksums\n", sector_count, bytes_count_nopi, (uint64_t)(bytes_count_nopi / 1000000000), bytes_count);
		}
	}

	if (read_bytes != 0) {
		fprintf(stderr, "error: read() on \"%s\": %m\n", argv[1]);
		goto theend;
	} else {
		fprintf(stderr, "\nSuccess!\n", argv[1]);
		rc = 0;
	}

theend:
	fprintf(stderr, "\nCopied:\n  %"PRIu64" sectors\n  %"PRIu64" data bytes\n  %"PRIu64" data bytes + T10-PI checksums\n", sector_count, bytes_count_nopi, bytes_count);
	
	close(infile);
	close(outfile);
	close(outfile2);

	if (rc !=0)
		fprintf(stderr, "Failed. See error message above the statistics.\n");

	return rc;
}
