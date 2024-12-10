/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <assert.h>
#include "ec_base.h"
#include "ec_session.h"
#include "em.h"
#include "aes_siv.h"

int ec_session_t::create_auth_req(unsigned char *buff)
{

    EC_KEY *responder_boot_key, *initiator_boot_key;
    unsigned int wrapped_len;

    unsigned short attrib_len, chann_attr;;
    unsigned char protocol_key_buff[1024];
    ULONG hm_channel = 0;
    ULONG ch_freq = 0;

    printf("%s:%d Enter\n", __func__, __LINE__);

    ec_frame_t    *frame = (ec_frame_t *)buff;
    attrib_len = 0;

    frame->frame_type = ec_frame_type_auth_req; 

    responder_boot_key = get_responder_boot_key();
    initiator_boot_key = get_initiator_boot_key();

    if (init_session() != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d Failed to initialize session parameters\n", __func__, __LINE__);
        return -1;
    }

    if (compute_intermediate_key(true) != 0) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d failed to generate key\n", __func__, __LINE__);
        return -1;
    }

    uint8_t* attribs = frame->attributes;

    if (compute_key_hash(initiator_boot_key, m_params.initiator_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        return -1;
    }

    attribs = add_attrib(attribs, ec_attrib_id_init_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.initiator_keyhash);
    attrib_len += get_ec_attr_size(SHA256_DIGEST_LENGTH);

    if (compute_key_hash(responder_boot_key, m_params.responder_keyhash) < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    attribs = add_attrib(attribs, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, m_params.responder_keyhash);
    attrib_len += get_ec_attr_size(SHA256_DIGEST_LENGTH);

    if (m_cfgrtr_ver > 1) {
        attribs = add_attrib(attribs, ec_attrib_id_proto_version, sizeof(m_cfgrtr_ver), &m_cfgrtr_ver);
        attrib_len += get_ec_attr_size(sizeof(m_cfgrtr_ver));
    }

    BN_bn2bin((const BIGNUM *)m_params.x,
            &protocol_key_buff[BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);
    BN_bn2bin((const BIGNUM *)m_params.y,
            &protocol_key_buff[2*BN_num_bytes(m_params.prime) - BN_num_bytes(m_params.x)]);

    attribs = add_attrib(attribs, ec_attrib_id_init_proto_key, 2*BN_num_bytes(m_params.prime), protocol_key_buff);
    attrib_len += get_ec_attr_size(2*BN_num_bytes(m_params.prime));

    chann_attr = freq_to_channel(channel_to_frequency(hm_channel)); //channel attrib shall be home channel
    attribs = add_attrib(attribs, ec_attrib_id_channel, sizeof(unsigned short), (unsigned char *)&chann_attr);
    attrib_len += get_ec_attr_size(sizeof(unsigned short));

    wrapped_len = set_auth_frame_wrapped_data(frame, attrib_len, true);
    attrib_len += get_ec_attr_size(wrapped_len);

    printf("%s:%d Exit\n", __func__, __LINE__);

    return attrib_len;

}

int ec_session_t::create_auth_rsp(unsigned char *buff)
{
    return -1;
}

int ec_session_t::create_auth_cnf(unsigned char *buff)
{
    return -1;
}

int ec_session_t::create_pres_ann(unsigned char *buff)
{

    ec_frame_t *frame = (ec_frame_t *)buff;
    frame->frame_type = ec_frame_type_presence_announcement; 

    EC_KEY * responder_boot_key = get_responder_boot_key();

    // Compute the hash of the responder boot key 
    unsigned char resp_boot_key_chirp_hash[SHA512_DIGEST_LENGTH];
    if (compute_key_hash(responder_boot_key, resp_boot_key_chirp_hash, "chirp") < 1) {
        m_activation_status = ActStatus_Failed;
        printf("%s:%d unable to compute \"chirp\" responder bootstrapping key hash\n", __func__, __LINE__);
        return -1;
    }

    uint8_t* attribs = frame->attributes;
    unsigned short attrib_len = 0;

    attribs = add_attrib(attribs, ec_attrib_id_resp_bootstrap_key_hash, SHA256_DIGEST_LENGTH, resp_boot_key_chirp_hash);
    attrib_len += get_ec_attr_size(SHA256_DIGEST_LENGTH); 

    return attrib_len;
}

int ec_session_t::handle_pres_ann(unsigned char *buff, unsigned int len)
{
    ec_frame_t *frame = (ec_frame_t *)buff;

    if (validate_frame(frame, ec_frame_type_presence_announcement) == false) {
        printf("%s:%d: frame validation failed\n", __func__, __LINE__);
        return -1;
    }

    ec_attribute_t *attrib = get_attrib(frame->attributes, len-EC_FRAME_BASE_SIZE, ec_attrib_id_resp_bootstrap_key_hash);
    if (!attrib) {
        return -1;
    }

    // TODO: Come back to this
    memcpy(m_params.responder_keyhash, attrib->data, attrib->length);

    return 0;	
}

bool ec_session_t::validate_frame(ec_frame_t *frame, ec_frame_type_t type)
{
    if ((frame->category != 0x04) 
            || (frame->action != 0x09)
            || (frame->oui[0] != 0x50)
            || (frame->oui[1] != 0x6f)
            || (frame->oui[2] != 0x9a)
            || (frame->oui_type != DPP_OUI_TYPE)
            || (frame->crypto_suite != 0x01)
            || (frame->frame_type != type)) {
        return false;
    }

    return true;
}

int ec_session_t::init_session()
{
    unsigned char keyasn1[1024];
    const unsigned char *key;
    unsigned int asn1len;
    EC_KEY *responder_key, *initiator_key;
    const EC_POINT *ipt, *rpt = NULL;
    const BIGNUM *proto_priv;

    if (m_data.type == ec_session_type_cfg) {
        memset(keyasn1, 0, sizeof(keyasn1));
        if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)m_data.rPubKey, strlen(m_data.rPubKey))) < 0) {
            printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
            return -1;
        }

        key = keyasn1;
        responder_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

        EC_KEY_set_conv_form(responder_key, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(responder_key, OPENSSL_EC_NAMED_CURVE);

        // get the group from responder's boot strap key information
        if ((m_params.group = EC_KEY_get0_group(responder_key)) == NULL) {
            printf("%s:%d Failed to get group from ec key\n", __func__, __LINE__);
            return -1;
        }

        rpt = EC_KEY_get0_public_key(responder_key);
        if (rpt == NULL) {
            printf("%s:%d Could not get responder bootstrap public key\n", __func__, __LINE__);
            return -1;
        }

        memset(keyasn1, 0, sizeof(keyasn1));
        if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)m_data.iPubKey, strlen(m_data.iPubKey))) < 0) {
            printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
            return -1;
        }

        key = keyasn1;
        initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

        EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

    } else if (m_data.type == ec_session_type_recfg) {
        memset(keyasn1, 0, sizeof(keyasn1));
        if ((asn1len = EVP_DecodeBlock(keyasn1, (unsigned char *)m_data.iPubKey, strlen(m_data.iPubKey))) < 0) {
            printf("%s:%d Failed to decode base 64 initiator public key\n", __func__, __LINE__);
            return -1;
        }

        key = keyasn1;
        initiator_key = d2i_EC_PUBKEY(NULL, &key, asn1len);

        EC_KEY_set_conv_form(initiator_key, POINT_CONVERSION_COMPRESSED);
        EC_KEY_set_asn1_flag(initiator_key, OPENSSL_EC_NAMED_CURVE);

        m_params.group = EC_KEY_get0_group(initiator_key);
        m_params.responder_connector = EC_POINT_new(m_params.group);
    }


    m_params.x = BN_new();
    m_params.y = BN_new();
    m_params.m = BN_new();
    m_params.n = BN_new();
    m_params.prime = BN_new();
    m_params.bnctx = BN_CTX_new();

    m_params.responder_proto_pt = EC_POINT_new(m_params.group);
    m_params.nid = EC_GROUP_get_curve_name(m_params.group);

    //printf("%s:%d nid: %d\n", __func__, __LINE__, m_params.nid);
    switch (m_params.nid) {
        case NID_X9_62_prime256v1:
            m_params.group_num = 19;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        case NID_secp384r1:
            m_params.group_num = 20;
            m_params.digestlen = 48;
            m_params.hashfcn = EVP_sha384();
            break;
        case NID_secp521r1:
            m_params.group_num = 21;
            m_params.digestlen = 64;
            m_params.hashfcn = EVP_sha512();
            break;
        case NID_X9_62_prime192v1:
            m_params.group_num = 25;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        case NID_secp224r1:
            m_params.group_num = 26;
            m_params.digestlen = 32;
            m_params.hashfcn = EVP_sha256();
            break;
        default:
            printf("%s:%d nid:%d not handled\n", __func__, __LINE__, m_params.nid);
            return -1;
    }

    m_params.noncelen = m_params.digestlen/2;

    //printf("%s:%d group_num:%d digestlen:%d\n", __func__, __LINE__, m_params.group_num, m_params.digestlen);

    m_params.initiator_proto_key = EC_KEY_new_by_curve_name(m_params.nid);
    if (m_params.initiator_proto_key == NULL) {
        printf("%s:%d Could not create protocol key\n", __func__, __LINE__);
        return -1;
    }

    if (EC_KEY_generate_key(m_params.initiator_proto_key) == 0) {
        printf("%s:%d Could not generate protocol key\n", __func__, __LINE__);
        return -1;
    }

    ipt = EC_KEY_get0_public_key(m_params.initiator_proto_key);
    if (ipt == NULL) {
        printf("%s:%d Could not get initiator protocol public key\n", __func__, __LINE__);
        return -1;
    }

    proto_priv = EC_KEY_get0_private_key(m_params.initiator_proto_key);
    if (proto_priv == NULL) {
        printf("%s:%d Could not get initiator protocol private key\n", __func__, __LINE__);
        return -1;
    }

    if ((m_params.N = EC_POINT_new(m_params.group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return -1;
    }


    if ((m_params.M = EC_POINT_new(m_params.group)) == NULL) {
        printf("%s:%d unable to create bignums to initiate DPP!\n", __func__, __LINE__);
        return -1;
    }


    if (EC_POINT_get_affine_coordinates_GFp(m_params.group, ipt, m_params.x,
                m_params.y, m_params.bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }

    if (m_data.type == ec_session_type_cfg) {

        if (EC_POINT_mul(m_params.group, m_params.M, NULL, rpt, proto_priv, m_params.bnctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return -1;
        }


        printf("Point M:\n");
        print_ec_point(m_params.group, m_params.bnctx, m_params.M);

        if (EC_POINT_get_affine_coordinates_GFp(m_params.group, m_params.M,
                    m_params.m, NULL, m_params.bnctx) == 0) {
            printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
            return -1;

        }
    }

    RAND_bytes(m_params.initiator_nonce, m_params.noncelen);
    if (EC_GROUP_get_curve_GFp(m_params.group, m_params.prime, NULL, NULL,
                m_params.bnctx) == 0) {
        printf("%s:%d unable to get x, y of the curve\n", __func__, __LINE__);
        return -1;
    }


    return 0;

}



int ec_session_t::set_auth_frame_wrapped_data(ec_frame_t *frame, unsigned int non_wrapped_len, bool auth_init)
{
    siv_ctx ctx;
    
    ec_attribute_t *attrib;
    ec_dpp_capabilities_t caps = {{
        .enrollee = 0,
        .configurator = 1
    }};
    unsigned int wrapped_len = 0;
    ec_attribute_t *wrapped_attrib;
    unsigned char *key;

    key = (auth_init == true) ? m_params.k1:m_params.ke;

    switch(m_params.digestlen) {
        case SHA256_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_256);
            break;
        case SHA384_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_384);
            break;
        case SHA512_DIGEST_LENGTH:
            siv_init(&ctx, key, SIV_512);
            break;
        default:
            printf("%s:%d Unknown digest length\n", __func__, __LINE__);
            return -1;
    }

    unsigned char plain[512];
    uint8_t* attribs = plain;

    if (auth_init == true) {
        attribs = add_attrib(attribs, ec_attrib_id_init_nonce, m_params.noncelen, m_params.initiator_nonce);
        wrapped_len += get_ec_attr_size(m_params.noncelen); 

        attribs = add_attrib(attribs, ec_attrib_id_init_caps, caps.byte);
        wrapped_len += get_ec_attr_size(1);
    } else {
        attribs = add_attrib(attribs, ec_attrib_id_init_auth_tag, m_params.digestlen, m_params.iauth);
        wrapped_len += get_ec_attr_size(m_params.digestlen);

    }

    wrapped_attrib = (ec_attribute_t *)(frame->attributes + non_wrapped_len);
    wrapped_attrib->attr_id = ec_attrib_id_wrapped_data;
    wrapped_attrib->length = wrapped_len + AES_BLOCK_SIZE;

    siv_encrypt(&ctx, plain, &wrapped_attrib->data[AES_BLOCK_SIZE], wrapped_len, wrapped_attrib->data, 2,
            frame, sizeof(ec_frame_t), // Used for SIV (authentication)
            frame->attributes, non_wrapped_len); // Used for SIV (authentication)

    //printf("%s:%d: Plain text:\n", __func__, __LINE__);
    //print_hex_dump(noncelen, plain);

    return wrapped_len + AES_BLOCK_SIZE;
}

ec_session_t::ec_session_t(ec_data_t *data)
{
    memcpy(&m_data, data, sizeof(ec_data_t));
}

ec_session_t::~ec_session_t()
{

}

ec_attribute_t *ec_session_t::get_attrib(unsigned char *buff, unsigned short len, ec_attrib_id_t id)
{
    unsigned int total_len = 0;
    ec_attribute_t *attrib = (ec_attribute_t *)buff;

    while (total_len < len) {
        if (attrib->attr_id == id) {
            return attrib;
        }

        total_len += (get_ec_attr_size(attrib->length));
        attrib = (ec_attribute_t *)((uint8_t*)attrib + get_ec_attr_size(attrib->length));
    }

    return NULL;
}


uint8_t* ec_session_t::add_attrib(unsigned char *buff, ec_attrib_id_t id, unsigned short len, unsigned char *data)
{
    if (buff == NULL || data == NULL || len == 0) {
        fprintf(stderr, "Invalid input\n");
        return NULL;
    }
    memset(buff, 0, get_ec_attr_size(len));
    ec_attribute_t *attr = (ec_attribute_t *)buff;
    // EC attribute id and length are in host byte order according to the spec (8.1)
    attr->attr_id = id;
    attr->length = len;
    memcpy(attr->data, data, len);

    // Return the next attribute in the buffer
    return buff + get_ec_attr_size(len);
}


unsigned short ec_session_t::channel_to_frequency(unsigned int channel)
{
    unsigned short frequency = 0;

    if (channel <= 14) {
        frequency = 2412 + 5*(channel - 1);
    } else if ((channel >= 36) && (channel <= 64)) {
        frequency = 5180 + 5*(channel - 36);
    } else if ((channel >= 100) && (channel <= 140)) {
        frequency = 5500 + 5*(channel - 100);
    } else if ((channel >= 149) && (channel <= 165)) {
        frequency = 5745 + 5*(channel - 149);
    }

    return frequency;
}

unsigned short ec_session_t::freq_to_channel(unsigned int freq)
{
    unsigned int temp = 0;
    int sec_channel = -1;
    unsigned int op_class = 0;
    if (freq) {
        if (freq >= 2412 && freq <= 2472){
            if (sec_channel == 1)
                op_class = 83;
            else if (sec_channel == -1)
                op_class = 84;
            else
                op_class = 81;

            temp = ((freq - 2407) / 5);
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

        /** In Japan, 100 MHz of spectrum from 4900 MHz to 5000 MHz
          can be used for both indoor and outdoor connection
         */
        if (freq >= 4900 && freq < 5000) {
            if ((freq - 4000) % 5)
                return 0;
            temp = (freq - 4000) / 5;
            op_class = 0; /* TODO */
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        if (freq == 2484) {
            op_class = 82; /* channel 14 */
            temp = 14;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 36..48 */
        if (freq >= 5180 && freq <= 5240) {
            if ((freq - 5000) % 5)
                return 0;

            if (sec_channel == 1)
                op_class = 116;
            else if (sec_channel == -1)
                op_class = 117;
            else
                op_class = 115;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 52..64 */
        if (freq >= 5260 && freq <= 5320) {
            if ((freq - 5000) % 5)
                return 0;

            if (sec_channel == 1)
                op_class = 119;
            else if (sec_channel == -1)
                op_class = 120;
            else
                op_class = 118;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 100..140 */
        if (freq >= 5000 && freq <= 5700) {
            if (sec_channel == 1)
                op_class = 122;
            else if (sec_channel == -1)
                op_class = 123;
            else
                op_class = 121;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
        /* 5 GHz, channels 149..169 */
        if (freq >= 5745 && freq <= 5845) {
            if (sec_channel == 1)
                op_class = 126;
            else if (sec_channel == -1)
                op_class = 127;
            else if (freq <= 5805)
                op_class = 124;
            else
                op_class = 125;

            temp = (freq - 5000) / 5;
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }

#if HOSTAPD_VERSION >= 210 //2.10
        if (is_6ghz_freq(freq)) {
            if (freq == 5935) {
                temp = 2;
                op_class = 131;
            } else {
                temp = (freq - 5950) % 5;
                op_class = 131 + center_idx_to_bw_6ghz((freq - 5950) / 5);
            }
            return ((((short)temp) << 8) | (0x00ff & op_class));
        }
#endif
    }
    printf("error: No case for given Freq\n");
    return 0;
}

void ec_session_t::print_hex_dump(unsigned int length, unsigned char *buffer)
{
    int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}