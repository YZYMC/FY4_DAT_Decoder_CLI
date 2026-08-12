/*
 * fy4dec.c
 *
 * Copyright 2026 ZiYuan Yang <yzymc@yzynetwork.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include <argp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <endian.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

char *datin = NULL;
bool sfileout = 0;
char fileout[128] = "decrypted.bin";
uint8_t deskey[8];
char *keyfilepath = NULL;

const char	*argp_program_version =
    "fy4dec 1.0\n"
    "Copyright 2026 ZiYuan Yang\n"
    "This is free software; see the source for copying conditions.  There is NO\n"
    "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n";
const char	*argp_program_bug_address = "yzymc@yzynetwork.org";

static struct argp_option options[] =
{
	{"output", 'o', "FILE", 0, "Output file path"},
    { "key-file", 'k', "FILE", 0, "DES Key binary file input"},
	{0}
};

static char	doc[]	   = "fy4dec -- FY4 LRIT DAT file decoder";
static char	args_doc[] = "DATFILE";

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	switch (key)
    {
        case 'o':
            sfileout = 1;
            strcpy(fileout, arg);
            break;
        
        case 'k':
            keyfilepath = arg;
            break;
        
    	case ARGP_KEY_ARG:
	    	if (state->arg_num >= 1)
	    		argp_usage(state);
	    	datin = arg;
	    	break;
        
        case ARGP_KEY_END:
		    if (state->arg_num < 1 || keyfilepath == NULL)
			    argp_usage(state);
		    break;
        
	    default:
	    	return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char **argv)
{
    argp_parse(&argp, argc, argv, 0, 0, NULL);

    FILE *datfile = fopen(datin, "rb");
    if (datfile == NULL)
    {
        perror("fopen");
        return 1;
    }

    FILE *keyfile = fopen(keyfilepath, "rb");
    if (keyfile == NULL)
    {
        perror("fopen");
        return 1;
    }

    if (fread(deskey, 1, sizeof(deskey), keyfile) != sizeof(deskey)) {
        return 1;
    }

    fclose(keyfile);

    char dat_filename[106];

    fseek(datfile, 0x46, SEEK_SET);
    fread(dat_filename, 1, 106, datfile);

    uint64_t bit_length;

    fseek(datfile, 0x08, SEEK_SET);
    fread(&bit_length, sizeof(bit_length), 1, datfile);

    bit_length = be64toh(bit_length);
    uint64_t byte_length = bit_length / 8;

    char filetype[4];

    fseek(datfile, 0xCB, SEEK_SET);
    fread(filetype, 1, 4, datfile);

    if (!sfileout)
    {
        strcpy(fileout, dat_filename);

        char *ext = strrchr(fileout, '.');

        if (strcmp(filetype, "JPG") == 0)
            strcpy(ext, ".JPG");
        else if (strcmp(filetype, "NC") == 0)
            strcpy(ext, ".NC\0");
        else
            strcpy(ext, ".BIN");
    }

    FILE *outfile = fopen(fileout, "wb");

    fseek(datfile, 0xE6, SEEK_SET);

    uint8_t readbuf[4096];
    uint8_t outbuf[4096+8];
    size_t n;
    int outlen;

    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");

    if (legacy == NULL)
    {
        fprintf(stderr, "Failed to load legacy provider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        fprintf(stderr, "Failed to create cipher context\n");
        return 1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, deskey, NULL) != 1)
    {
        fprintf(stderr, "DecryptInit failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    uint64_t decrypted_length = 0;

    while ((n = fread(readbuf, 1, sizeof(readbuf), datfile)) > 0)
    {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, readbuf, n) != 1)
        {
            fprintf(stderr, "Decrypt failed\n");
            return 1;
        }
        fwrite(outbuf, 1, outlen, outfile);
        decrypted_length += outlen;
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1)
    {
        fprintf(stderr, "Decrypt final failed\n");
        return 1;
    }

    fwrite(outbuf, 1, outlen, outfile);
    decrypted_length += outlen;

    EVP_CIPHER_CTX_free(ctx);
    OSSL_PROVIDER_unload(legacy);

    fclose(datfile);
    fclose(outfile);

    if (byte_length != decrypted_length)
    {
        fprintf(stderr,
            "Warning: plaintext length mismatch: "
            "expected %" PRIu64 " bytes, got %" PRIu64 " bytes\n",
            byte_length,
            decrypted_length);
    }

    return 0;
}