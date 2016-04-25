// HexToSyx.cpp : Defines the entry point for the console application.
//

#include "stdio.h"
#include "string.h"
#include "ctype.h"
#include "stdlib.h"

/*
:020000040000FA
:08000000B731052800000000E3
:0C3E00008A01000000008A018200FB2FF4
:0E3E120022000C110C152000A2012000911EB0
:103E20000E2F230019082000A000F0302005A70065
:103E30002708F03A031D442F2008F83A03190E2FE3
:103E4000023A03190E2F013A03190E2F073A0319EC
:103E50000E2F0C3A0319302F073A0319362F0E2F65
:103E6000A208031D322F0230A2000E2F2208013AB1
:103E700003190E2F013A03190E2F053A031D432F84
:103E8000A30803190800432F80302005A800A901CA
:103E9000A8080319A90AA908031D562F2208003AE9
:103EA00003190E2F013A03190E2F552F2208003A3D
:103EB00003190E2F013A03190E2F033A03196D2F20
:103EC000013A0319762F073A0319802F013A031993
:103ED0008E2F033A0319942F0E2FA008031D732F62
:103EE0000330A2000E2F0130A2000E2F20087F3ACF
:103EF000031D7D2F0430A2000E2F0130A2000E2FD3
:103F00002008123A031D8B2FA3010530A2002200C6
:103F10000C150C150E2F0130A2000E2F200EF039BB
:103F2000A1000630A2000E2F0F302005AA002A089B
:103F3000A1040530A2002308003A0319A92F013A71
:103F40000319AE2F033A0319B32F013A0319B82FFF
:103F50000E2F2108A4000130A3000E2F2108A50078
:103F60000230A3000E2F2108A6000330A3000E2F5D
:103F70003730250203180E2FA508031DCB2F043060
:103F800026020318CB2F373023009200200026088A
:103F900023009100D22F250823009200200026083C
:103FA00023009100951715158B1355309600AA30F4
:103FB0009600951400000000000095102000A40B4E
:103FC000E32FA3010E2FA60A0E2F7A3021009900AD
:103FD00023009E01B0309D0008309F009C011F30DF
:103FE0009B00FB3021008C008E0020008E1D0927D5
:0A3FF0009F31002808009831E52FEA
:020000040001F9
:02000E00A4FF4D
:02001000FFDE11
:00000001FF


OUTPUT FORMAT,
multiple blocks of the following format

0xF0 <id1> <id2> <id3> 
<seq>														sequence number 0..127 increments, wraps around
<len_nybble1><len_nybble0>									number of data bytes
<addr_nybble3><addr_nybble2><addr_nybble1><addr_nybble0>	address
<data0_nybble1><data0_nybble0>
<data1_nybble1><data1_nybble0>
:
<datan_nybble1><datan_nybble0>
0xF7

 0123456789
:02001000FFDE11
 ^^-------------- byte count
   ^^^^---------- address
       ^^-------- record type
	     ^^^^---- data
		     ^^-- checksum
*/

#define SYSEX_START	0xF0
#define SYSEX_ID0	0x00
#define SYSEX_ID1	0x7F
#define SYSEX_ID2	0x11
#define SYSEX_END	0xF7

#define MAX_LINE 1000

char from_hex(char in) {
	switch (toupper(in)) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'A': return 10;
	case 'B': return 11;
	case 'C': return 12;
	case 'D': return 13;
	case 'E': return 14;
	case 'F': return 15;
	}
	return 0;
}
bool process_file(FILE *infile, FILE *outfile)
{
	int line = 0; // line number (for error message)
	int msg_sequence = 0; // sequence number for sysex message

	// loop through the input file
	while (!feof(infile)) {

		++line;

		// read a line
		char buf[MAX_LINE + 1];
		if (!fgets(buf, MAX_LINE, infile)) {
			break;
		}
		buf[MAX_LINE] = '\0';

		// should start with :
		if (buf[0] != ':') {
			printf("Hex file error - invalid data at line %d\n", line);
			return false;
		}

		// trim off any trailing line delimiters
		int line_len = strlen(buf);
		while (buf[line_len - 1] == '\r' || buf[line_len - 1] == '\n') {
			--line_len;
		}

		// check line is longer than minimum length
		if (line_len < 9) {
			printf("Hex file error - line too short to be valid at %d\n", line);
			return false;
		}

		// check for record type 0
		if (buf[6] != '0' || buf[7] != '0') { 
			continue;
		}

		// check that the declared data length matches the line length
		int data_len = 16 * from_hex(buf[1]) + from_hex(buf[2]);
		if (2 * data_len + 11 != line_len) { // remembering :
			printf("Hex file error - line length does not match data length at line %d\n", line);
			return false;
		}

		// write record to sysex
		fputc(SYSEX_START, outfile);		// } start tag
		fputc(SYSEX_ID0, outfile);			// } manufacturer id
		fputc(SYSEX_ID1, outfile);			// }
		fputc(SYSEX_ID2, outfile);			// }
		fputc(msg_sequence, outfile);		// sequence number
		fputc(from_hex(buf[1]), outfile);	// } number of data bytes
		fputc(from_hex(buf[2]), outfile);	// }
		fputc(from_hex(buf[3]), outfile);	// } address
		fputc(from_hex(buf[4]), outfile);	// }
		fputc(from_hex(buf[5]), outfile);	// }
		fputc(from_hex(buf[6]), outfile);	// }
		int data_pos = 9;
		for (int i = 0; i < data_len; ++i) {
			fputc(from_hex(buf[data_pos++]), outfile);
			fputc(from_hex(buf[data_pos++]), outfile);
		}
		fputc(SYSEX_END, outfile);			// } end tag

		// advance the sequence number
		++msg_sequence;
		msg_sequence &= 0x7F;
	}
}

int main(int argc, char *argv[])
{
	if(argc)
	FILE * infile = fopen("c:\\temp\\test.hex", "rt");
	if (!infile) {
		printf("input file not found\n");
		exit(1);
	}
	FILE * outfile = fopen("c:\\temp\\test.syx", "wb");
	if (!outfile) {
		printf("cannot open output file\n");
		exit(2);
	}
	if (process_file(infile, outfile)) {
		printf("done\n");
	}
	fclose(outfile);
	fclose(infile);
	return 0;
}
