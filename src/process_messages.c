#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdlib.h>
#include "process_messages.h"

char* g_error_message[] =
{
    "ОК",
    "Error: reading input file",
    "Error: writing output file",
    "Error: wrong message length",
    "Error: wrong symbol instead of hex digit",
    "Error: wrong length in the message",
    "Error: mask without message",
    "Error: message without mask",
    "Error: the input file doesn't have keywords for message an mask",
    "Error: CRC-32 calculated is not CRC-32 in the message",
    "Error: wrong initial parameters in file reading initialization",
    "Error: memory allocation function returned NULL"
};

char g_keyword_message[] = "mess=";
char g_keyword_mask[] = "mask=";

char* g_keyword[] =
{
    g_keyword_message,
    g_keyword_mask
};

typedef struct {
    FILE *file;
    char *string_buffer;
    size_t string_buffer_size;
} file_reading_control_t;

#define CRC32_POLYNOMIAL 0x04c11db7
#define CRC32_POLYNOMIAL_REVERSED 0xedb88320
#define CRC32_INITIAL 0xffffffff

// Notice that this function for CRC-32 is adapted for input bytes in ASCII hex format, i.e.,
// each hexbyte (two hex chars) is translated to a byte (an unsigned char) and then
// processed for CRC-32 calculation. The result (CRC-32 code) is 4 bytes (unsigned long).
unsigned long crc32custom(const char *string_of_hexchars, int number_of_bytes)
{
    unsigned long crc = ~CRC32_INITIAL;
    unsigned long byte = 0;
    for(int i = 0; i < number_of_bytes; i++) {
        const char *hexbyte = string_of_hexchars + i * NUMBER_OF_HEX_IN_BYTE;
        int ret_code = hexbyte_to_number(hexbyte, &byte);
        ASSERT(ret_code >= 0);
        crc ^= byte;
        for(int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (CRC32_POLYNOMIAL_REVERSED & -(crc & 1));
        }
    }
    return ~crc;
}

static int letter_to_digit(unsigned char letter)
{
    if ((letter >= '0') && (letter <= '9')) {
        return letter - '0';
    } else {
        if ((letter >= 'a') && (letter <= 'f')) {
            return letter - 'a' + 10;
        } else {
            if((letter >= 'A') && (letter <= 'F')) {
                return letter - 'A' + 10;
            }
            return ERROR_WRONG_DIGIT;
        }
    }
}

static int hexstring_to_number(const char *hexstring, unsigned long *number_p,
                               int number_of_hex)
{
    if ((number_of_hex < 1) || (number_of_hex > 8))
        return ERROR_HEXSTRING_FORMAT;
    if (strlen(hexstring) < number_of_hex)
        return ERROR_HEXSTRING_FORMAT;

    long number = 0;
    for (int i = 0; i < number_of_hex; i++) {
        int shift = (number_of_hex - i - 1) * 4;
        int digit = letter_to_digit(hexstring[i]);
        if (digit < 0) {
            int error_code = digit;
            return error_code;
        }
        number |= (digit << shift);
    }
    *number_p = number;
    return NO_ERROR;
}

int hextetrad_to_number(const char *hextetrad, unsigned long *number_p)
{
  return hexstring_to_number(hextetrad, number_p, NUMBER_OF_HEX_IN_TETRADS);
}

int hexbyte_to_number(const char *hexbyte, unsigned long *number_p)
{
  return hexstring_to_number(hexbyte, number_p, NUMBER_OF_HEX_IN_BYTE);
}

int number_to_hextetrad(unsigned long number, char *hextetrad)
{
  return (sprintf(hextetrad, "%08lx", number) == NUMBER_OF_HEX_IN_TETRADS) ?
                                                 NO_ERROR :
                                                 ERROR_NUMBER_TO_TETRADSTR;
}

int number_to_hexbyte(unsigned long number, char *hexbyte)
{
  return (sprintf(hexbyte, "%02lx", number) == NUMBER_OF_HEX_IN_BYTE) ?
                                               NO_ERROR :
                                               ERROR_NUMBER_TO_BYTESTR;
}

char* get_error_message(int error_code)
{
    int index_of_error_message = -error_code;
    if (index_of_error_message >= SIZE_OF_ARRAY(g_error_message))
        return "Unknown error";
    return g_error_message[index_of_error_message];
}

int get_message_struct(const char *message_hexstr, message_t *message)
{
    assert(message);
    assert(TYPE_IN_HEX_CHARS + LENGTH_IN_HEX_CHARS + DATA_MAX_SIZE_IN_HEX_CHARS +
           CRC32_IN_HEX_CHARS == MESSAGE_IN_HEX_CHARS);

    DEBUG_INT_D(strlen(message_hexstr));
    if (strlen(message_hexstr) != MESSAGE_IN_HEX_CHARS)
        return ERROR_MESSAGE_LENGTH;

    message->message_hexstr = message_hexstr;
    const char *remaining_hexstr = message_hexstr;

    message->type_hexstring[0] = '\0';
    strncat(message->type_hexstring, remaining_hexstr, TYPE_IN_HEX_CHARS);
    unsigned long type;
    int check_type_decoding = hexbyte_to_number(remaining_hexstr, &type);
    if (check_type_decoding < 0)
        return check_type_decoding;
    remaining_hexstr += TYPE_IN_HEX_CHARS;

    message->length_hexstring[0] = '\0';
    strncat(message->length_hexstring, remaining_hexstr, LENGTH_IN_HEX_CHARS);
    unsigned long length_in_bytes;
    int check_length_decoding = hexbyte_to_number(remaining_hexstr, &length_in_bytes);
    if (check_length_decoding < 0)
        return check_length_decoding;
    remaining_hexstr += LENGTH_IN_HEX_CHARS;

    if((length_in_bytes <= 0) || (length_in_bytes > DATA_MAX_SIZE_IN_ORIGINAL_BYTES )) {
        return ERROR_WRONG_LENGTH_IN_MESSAGE;
    }

    message->length_in_bytes = length_in_bytes;
    DEBUG_PRINTF("%ld", length_in_bytes);

    message->data_hexstring[0] = '\0';
    strncat(message->data_hexstring, remaining_hexstr, DATA_MAX_SIZE_IN_HEX_CHARS);
    message->data_hexstring_ptr = remaining_hexstr;
    int data_bytes_processed = 0;
    int data_tetrads_processed = 0;
    unsigned long data_number;
    const char *tetrad_hexstring;
    char tetrad_for_padding[NUMBER_OF_HEX_IN_TETRADS];

    while(data_bytes_processed < length_in_bytes) {
        int remaining_bytes = (length_in_bytes - data_bytes_processed);
        if (remaining_bytes >= NUMBER_OF_BYTES_IN_TETRADS) {
            tetrad_hexstring = message->data_hexstring_ptr +
                               data_bytes_processed * NUMBER_OF_HEX_IN_BYTE;
            DEBUG_PRINT_TETRAD(tetrad_hexstring);
        } else {
            int number_of_char_to_copy = remaining_bytes * NUMBER_OF_HEX_IN_BYTE;
            const char *remaining = message->data_hexstring_ptr +
                                    data_bytes_processed * NUMBER_OF_HEX_IN_BYTE;
            for(int i = 0; i < NUMBER_OF_HEX_IN_TETRADS; i++) {
                if (i < number_of_char_to_copy)
                    tetrad_for_padding[i] = remaining[i];
                else
                    tetrad_for_padding[i] = '0';
            }
            DEBUG_PRINT_TETRAD(tetrad_for_padding);
            tetrad_hexstring = tetrad_for_padding;
        }

        int check_tetrad = hextetrad_to_number(tetrad_hexstring, &data_number);
        if (check_tetrad < 0)
            return check_tetrad;
        message->data_as_numbers_in_tetrads[data_tetrads_processed] = data_number;
        DEBUG_PRINTF("%08lx", message->data_as_numbers_in_tetrads[data_tetrads_processed]);
        ++data_tetrads_processed;
        data_bytes_processed += NUMBER_OF_BYTES_IN_TETRADS;
    }

    message->number_of_tetrads_in_data = data_tetrads_processed;

    message->crc32_hexstring[0] = '\0';
    strncat(message->crc32_hexstring, message->data_hexstring_ptr + DATA_MAX_SIZE_IN_HEX_CHARS,
            CRC32_IN_HEX_CHARS);

    unsigned long crc32_number;
    int check_crc32_translation = hextetrad_to_number(message->crc32_hexstring, &crc32_number);
    if (check_crc32_translation < 0)
        return check_crc32_translation;
    message->crc32 = crc32_number;
    DEBUG_PRINTF("%08lx", message->crc32);

    return NO_ERROR;
}

int check_crc32(const message_t *message_struct)
{
    unsigned long crc32_calculated = crc32custom(message_struct->data_hexstring,
                                                 message_struct->length_in_bytes);
    if (crc32_calculated != message_struct->crc32)
        return ERROR_CRC32;

    return NO_ERROR;
}

int apply_mask(message_t *message_struct, const char *mask)
{
    unsigned long mask_as_number;
    int ret_code = hextetrad_to_number(mask, &mask_as_number);
    if (ret_code < 0)
        return ret_code;
    DEBUG_PRINTF("%08lx", mask_as_number);

    for (int i = 0; i < message_struct->number_of_tetrads_in_data; i++) {
        int this_is_even_tetrad = (i % 2 == 0);
        if (this_is_even_tetrad) {
            message_struct->data_as_numbers_in_tetrads[i] ^= mask_as_number;
        }
    }
    return NO_ERROR;
}

int get_modified_data_and_crc32(message_t *message_struct)
{
    char *data_hexstring_current_position = message_struct->data_hexstring_modified;
    for (int i = 0; i < message_struct->number_of_tetrads_in_data; i++) {
        int ret_code = number_to_hextetrad(message_struct->data_as_numbers_in_tetrads[i],
                                           data_hexstring_current_position);
        if (ret_code < 0)
            return ret_code;
        data_hexstring_current_position += NUMBER_OF_HEX_IN_TETRADS;
    }

    int length_in_bytes_modified = message_struct->number_of_tetrads_in_data *
                                   NUMBER_OF_BYTES_IN_TETRADS;

    DEBUG_STRING(message_struct->data_hexstring_modified);
    message_struct->crc32_modified = crc32custom(message_struct->data_hexstring_modified,
                                                 length_in_bytes_modified);

    DEBUG_PRINTF("%08lx", message_struct->crc32_modified);

    return NO_ERROR;
}

int process_pair(const char *message, const char *mask, message_t *message_struct)
{
    int ret_code = NO_ERROR;
    assert(NULL != message_struct);

    if ((NULL == message) && (NULL != mask)) {
        ret_code = ERROR_MASK_WITHOUT_MESSAGE;
    } else {
        if ((NULL != message) && (NULL == mask)) {
            ret_code = ERROR_MESSAGE_WITHOUT_MASK;
        } else {
            if ((NULL == message) && (NULL == mask)) {
                ret_code = ERROR_THERE_IS_NO_MESSAGE_OR_MASK;
            } else {
                if ((ret_code = get_message_struct(message, message_struct)) == NO_ERROR) {
                    if ((ret_code = check_crc32(message_struct)) == NO_ERROR) {
                        if ((ret_code = apply_mask(message_struct, mask)) == NO_ERROR) {
                            ret_code = get_modified_data_and_crc32(message_struct);
                        }
                    }
                }
            }
        }
    }

    DEBUG_INT_D(ret_code);
    return ret_code;
}

int get_string_from_file_on_next_char(const file_reading_control_t *reading_settings_ptr,
                                      char **string_ptr)
{
    static file_reading_control_t s_reading_settings;

    int ret_code = NO_ERROR;

    int initial_call = (NULL != reading_settings_ptr);

    if (initial_call) {
        if ((NULL == reading_settings_ptr->file) || (NULL == reading_settings_ptr->string_buffer) ||
            (reading_settings_ptr->string_buffer_size < 2))
            return ERROR_INIT_FILE_READING;

        s_reading_settings = *reading_settings_ptr;
        rewind(s_reading_settings.file);
    } else {
        size_t size_to_read = s_reading_settings.string_buffer_size - 1;
        DEBUG_INT_D(size_to_read);
        DEBUG_PRINTF("%ld", ftell(s_reading_settings.file));
        DEBUG_PRINTF("%p", s_reading_settings.file);
        size_t chars_read = fread(s_reading_settings.string_buffer,
                                  1, size_to_read, s_reading_settings.file);
        DEBUG_INT_D(chars_read);
        assert(chars_read <= size_to_read);
        s_reading_settings.string_buffer[chars_read] = '\0';
        int offset_to_char_next_to_the_first_read = 1 - chars_read;
        if (fseek(s_reading_settings.file, offset_to_char_next_to_the_first_read, SEEK_CUR) != 0)
            return ERROR_FILE_READ;
        *string_ptr = s_reading_settings.string_buffer;
        ret_code = chars_read;
    }

    return ret_code;
}

int read_after_keyword(FILE *file, const char*keyword, char *where_to_read, int length)
{
    int ret_code = NO_ERROR;
    int offset_already_done_to_next_char = 1;
    int offset_to_end_of_keyword_from_its_beginning = strlen(keyword) -
                                                      offset_already_done_to_next_char;
    if (fseek(file, offset_to_end_of_keyword_from_its_beginning, SEEK_CUR) != 0)
        return ERROR_FILE_READ;
    size_t chars_read = fread(where_to_read, 1, length, file);
    assert(chars_read <= length);
    if (chars_read < length) {
        return ERROR_MESSAGE_LENGTH;
    }
    where_to_read[chars_read] = '\0';
    return ret_code;
}

int get_message_and_mask_pair(const file_reading_control_t *reading_settings_ptr,
                              char *message, char *mask)
{
    static FILE *s_file = NULL;
    static int s_at_least_one_pair_found = 0;

    int ret_code = NO_ERROR;
    int chars_read = 0;

    int initial_call = (NULL != reading_settings_ptr);

    if (initial_call) {
        s_file = reading_settings_ptr->file;
        s_at_least_one_pair_found = 0;
        const file_reading_control_t *initializing = reading_settings_ptr;
        if ((ret_code = get_string_from_file_on_next_char(initializing, NULL)) < 0) {
            return ret_code;
        }
    } else {
        char *string_from_file;
        int keyword_message_found = 0;
        int keyword_mask_found = 0;
        int pair_found_break = 0;
        while (!feof(s_file)) {
            chars_read = 0;
            if ((chars_read = get_string_from_file_on_next_char(NULL, &string_from_file)) < 0) {
                ret_code = chars_read;
                return ret_code;
            }
            int end_of_file_or_something_else = (0 == chars_read);
            if (end_of_file_or_something_else)
                break;
            DEBUG_STRING(string_from_file);
            if (strlen(string_from_file) == 0)
                continue;
            char *keyword_found = NULL;
            for (int i = 0; i < SIZE_OF_ARRAY(g_keyword); i++) {
                if (strcmp(string_from_file, g_keyword[i]) == 0) {
                    keyword_found = g_keyword[i];
                    break;
                }
            }
            if (keyword_found == g_keyword_message) {
                int new_keyword_is_again_message = (keyword_message_found);
                if (new_keyword_is_again_message) {
                    return ERROR_MESSAGE_WITHOUT_MASK;
                }
                keyword_message_found = 1;
                if ((ret_code = read_after_keyword(s_file, keyword_found,
                                                   message, MESSAGE_IN_HEX_CHARS)) <0 )
                    return ret_code;
            } else {
                if (keyword_found == g_keyword_mask) {
                    int message_not_found_for_this_mask = (!keyword_message_found);
                    if (message_not_found_for_this_mask) {
                        return ERROR_MASK_WITHOUT_MESSAGE;
                    }
                    keyword_mask_found = 1;
                    if ((ret_code = read_after_keyword(s_file, keyword_found,
                                                       mask, MASK_IN_HEX_CHARS)) <0 )
                        return ret_code;
                    pair_found_break = 1;
                    s_at_least_one_pair_found = 1;
                    break;
                }
            }
        }
        int this_is_eof_and_pair_not_found = (!pair_found_break);
        if (this_is_eof_and_pair_not_found) {
            DEBUG_MSG("this_is_eof_and_pair_not_found");
            assert(!((keyword_message_found) && (keyword_mask_found)));
            assert(!((!keyword_message_found) && (keyword_mask_found)));
            if ((keyword_message_found) && (!keyword_mask_found))
                return ERROR_MESSAGE_WITHOUT_MASK;
            if (!s_at_least_one_pair_found)
                if ((!keyword_message_found) && (!keyword_mask_found))
                    return ERROR_THERE_IS_NO_MESSAGE_OR_MASK;
        }
        DEBUG_INT_D(chars_read);
        ret_code = chars_read;
    }
    DEBUG_INT_D(ret_code);
    return ret_code;
}

size_t get_keyword_max_length()
{
    size_t max_length = 0;
    size_t current_length;
    for (int i = 0; i < SIZE_OF_ARRAY(g_keyword); i++) {
        current_length = strlen(g_keyword[i]);
        if (current_length > max_length)
            max_length = current_length;
    }
    return max_length;
}


int process_all_messages(const char *in_file_name, const char *out_file_name,
                         const options_t *options)
{
    int ret_code = NO_ERROR;
    FILE *fo = NULL;
    FILE *fi = NULL;
    file_reading_control_t reading_settings;
    reading_settings.string_buffer = NULL;

    if (NULL == (fo = fopen(out_file_name, "wt"))) {
        ret_code = ERROR_FILE_WRITE;
        goto cleanup_and_return;
    }

    if (NULL == (fi = fopen(in_file_name, "rb"))) {
        ret_code = ERROR_FILE_READ;
        goto cleanup_and_return;
    }

    char message[MESSAGE_IN_HEX_CHARS + 1];
    char mask[MASK_IN_HEX_CHARS + 1];

    reading_settings.file = fi;
    DEBUG_PRINTF("%p", reading_settings.file);

    size_t keyword_max_length = get_keyword_max_length();
    assert(keyword_max_length > 0);
    reading_settings.string_buffer_size = keyword_max_length + 1;

    if (NULL == (reading_settings.string_buffer = malloc(reading_settings.string_buffer_size))) {
        ret_code = ERROR_MEMORY_ALLOCATION;
        goto cleanup_and_return;
    }

    const file_reading_control_t *initializing = &reading_settings;
    if ((ret_code = get_message_and_mask_pair(initializing, NULL, NULL)) < 0) {
        goto cleanup_and_return;
    }

    while (!feof(reading_settings.file)) {
        DEBUG_MSG("----- Searching new message and mask pair ...");
        int chars_read;
        if ((chars_read = get_message_and_mask_pair(NULL, message, mask)) < 0) {
            ret_code = chars_read;
            goto cleanup_and_return;
        }
        int end_of_file_or_something_else = (0 == chars_read);
        if (end_of_file_or_something_else)
            break;
        DEBUG_MSG("---------- Message and mask are found in the input file");
        DEBUG_STRING(message);
        DEBUG_STRING(mask);
        DEBUG_INT_D(chars_read);
        DEBUG_MSG("---------- Processing message and mask");
        message_t message_struct;
        if ((ret_code = process_pair(message, mask, &message_struct)) < 0)
            goto cleanup_and_return;
        DEBUG_MSG("---------- Writing to the output file");
        if (options->formatted_output)
            if (fprintf(fo, "\n\nmessage type:\n") < 0) {
                ret_code = ERROR_FILE_WRITE;
                goto cleanup_and_return;
            }
        if (fprintf(fo, "%s", message_struct.type_hexstring) < 0) {
            ret_code = ERROR_FILE_WRITE;
            goto cleanup_and_return;
        }
        if (options->formatted_output)
            if (fprintf(fo, "\ninitial message length:\n") < 0) {
                ret_code = ERROR_FILE_WRITE;
                goto cleanup_and_return;
            }
        if (fprintf(fo, "%s", message_struct.length_hexstring) < 0) {
            ret_code = ERROR_FILE_WRITE;
            goto cleanup_and_return;
        }
        if (options->formatted_output)
            if (fprintf(fo, "\ninitial message data bytes:\n") < 0) {
                ret_code = ERROR_FILE_WRITE;
                goto cleanup_and_return;
            }
        if (fprintf(fo, "%s", message_struct.data_hexstring) < 0) {
            ret_code = ERROR_FILE_WRITE;
            goto cleanup_and_return;
        }
        if (options->formatted_output)
            if (fprintf(fo, "\ninitial CRC-32:\n") < 0) {
                ret_code = ERROR_FILE_WRITE;
                goto cleanup_and_return;
            }
        if (fprintf(fo, "%s", message_struct.crc32_hexstring) < 0) {
            ret_code = ERROR_FILE_WRITE;
            goto cleanup_and_return;
        }

        int length_modified = message_struct.number_of_tetrads_in_data * NUMBER_OF_BYTES_IN_TETRADS;
        if (options->formatted_output)
            if (fprintf(fo, "\nmodified message length:\n") < 0) {
                ret_code = ERROR_FILE_WRITE;
                goto cleanup_and_return;
            }
        if (fprintf(fo, "%02x", length_modified) < 0) {
            ret_code = ERROR_FILE_WRITE;
            goto cleanup_and_return;
        }

        int offset_to_end_of_modified_data = length_modified * NUMBER_OF_HEX_IN_BYTE;
        int j = offset_to_end_of_modified_data;
        for (; j < DATA_MAX_SIZE_IN_HEX_CHARS; j++) {
            message_struct.data_hexstring_modified[j] = message_struct.data_hexstring_ptr[j];
        }
        message_struct.data_hexstring_modified[j] = '\0';
        if (options->formatted_output)
            if (fprintf(fo, "\nmodified message data bytes with mask:\n") < 0) {
                ret_code = ERROR_FILE_WRITE;
                goto cleanup_and_return;
            }
        if (fprintf(fo, "%s", message_struct.data_hexstring_modified) < 0) {
            ret_code = ERROR_FILE_WRITE;
            goto cleanup_and_return;
        }
        if (fprintf(fo, "%s", mask) < 0) {
            ret_code = ERROR_FILE_WRITE;
            goto cleanup_and_return;
        }
        if (options->formatted_output)
            if (fprintf(fo, "\nmodified CRC-32:\n") < 0) {
                ret_code = ERROR_FILE_WRITE;
                goto cleanup_and_return;
            }
        if (fprintf(fo, "%08lx", message_struct.crc32_modified) < 0) {
            ret_code = ERROR_FILE_WRITE;
            goto cleanup_and_return;
        }
    }

cleanup_and_return:
    if (ret_code < 0) {
        if (NULL != fo)
            fclose(fo);
        if (NULL == (fo = fopen(out_file_name, "wt")))
            ret_code = ERROR_FILE_WRITE;
        else
            fprintf(fo, "%s\n", get_error_message(ret_code));
    }
    if (NULL != reading_settings.string_buffer)
        free(reading_settings.string_buffer);
    if (NULL != fi)
        fclose(fi);
    if (NULL != fo)
        fclose(fo);
    return ret_code;
}

