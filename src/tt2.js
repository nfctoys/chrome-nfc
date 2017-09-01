/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0
  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @fileoverview 
 */

'use strict';


function TT2(tag_id) {
  this.tag_id = new Uint8Array(tag_id);
  this.type_name = null;  // vendor and its card name

  /*
   * TODO: detect at beginning -- if we have a reliable way to detect.
   *   this.detect_type_name(cb);
  */

  this.lock_contorl = [];
}

TT2.prototype.detect_type_name = function(cb) {
  var self = this;
  var callback = cb;

  if (this.tag_id[0] == 0x04) {
    // NxP, Try to read page 0x10. If success, it is Ultralight C.
    this.device.read_block(0x10, function(rc, bn) {
      if (rc) {
        self.type_name = "Mifare Ultralight";
      } else {
        self.type_name = "Mifare Ultralight C";
      }

      console.debug("[DEBUG] TT2.type_name = " + self.type_name);
      if (callback) callback();
    });
  }
}


// read NFC Type 2 tag spec 1.0 for memory structure.
// The callback is called with cb(NDEF Uint8Array).
TT2.prototype.read = function(device, cb) {
  var self = this;
  if (!cb) cb = defaultCallback;
  var callback = cb;

  function poll_block0(rc, b0_b3) {
    if (rc) return callback(rc);

    var card = new Uint8Array(b0_b3);
    var data = new Uint8Array(b0_b3);
    var data_size = data[14] * 8;  // CC2: unit is 8 bytes.
    var block = 4;  // data starts from block 4
    var writable_blocks = [4, 8, 12, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128]
    var writable_data = new Uint8Array();

    log('pages 0-3', UTIL_BytesToHex(data));

    // poll data out
    var poll_n = Math.floor((data_size + 15) / 16);

    function poll_block(card, block, poll_n) {
      console.log("[DEBUG] poll_n: " + poll_n);
      if (--poll_n < 0) {
        defaultCallback("[DEBUG] got a type 2 tag:", card.buffer);
      }

      device.read_block(block, function(rc, bn) {
        if (rc) return callback(rc);
        var newbn = new Uint8Array(bn)
        card = UTIL_concat(card, newbn);
        log('pages ' + block + '-' + (block+3), UTIL_BytesToHex(newbn));
        if (writable_blocks.indexOf(block) > -1) {
          if (block == 12) {
            writable_data = UTIL_concat(writable_data, newbn.subarray(0,4));
          } else if (block == 128) {
            writable_data = UTIL_concat(writable_data, newbn.subarray(0,8));
          } else {
            writable_data = UTIL_concat(writable_data, newbn);
          };
        };
        if (block == 132) {
          log('writable_data length', writable_data.length);
          var d = new TextDecoder('utf-8');
          var str = d.decode(writable_data);
          log('writable_data', str)
        };
        return poll_block(card, block + 4, poll_n);
      });
    }
    poll_block(card, block, poll_n);
  }

  device.read_block(0, poll_block0);
}


/* Input:
 *   ndef - Uint8Array
 */
TT2.prototype.compose = function(ndef) {

  var blen;  // CC2
  var need_lock_control_tlv = 0;

  if ((ndef.length + 16 /* tt2_header */
                   + 2  /* ndef_tlv */
                   + 1  /* terminator_tlv */) > 64) {
    /*
     * CC bytes of MF0ICU2 (MIFARE Ultralight-C) is OTP (One Time Program).
     * Set to maximum available size (144 bytes).
     */
    blen = 144 / 8;
    need_lock_control_tlv = 1;

    /* TODO: check if the ndef.length + overhead are larger than card */
  } else {
    /*
     * CC bytes of MF0ICU1 (MIFARE Ultralight) is OTP (One Time Program).
     * Set to maximum available size (48 bytes).
     */
    blen = 48 / 8;
  }

  var tt2_header = new Uint8Array([
    0x00, 0x00, 0x00, 0x00,  /* UID0, UID1, UID2, Internal0 */
    0x00, 0x00, 0x00, 0x00,  /* UID3, UID4, UID5, UID6 */
    0x00, 0x00, 0x00, 0x00,  /* Internal1, Internal2, Lock0, Lock1 */
    0xe1, 0x10, blen, 0x00   /* CC0, CC1, CC2(len), CC3 */
  ]);

  var lock_control_tlv = (need_lock_control_tlv) ?
    new Uint8Array([
      /*T*/ 0x01,
      /*L*/ 0x03,
      /*V*/ 0xA0, 0x10, 0x44  /* BytesLockedPerLockBit=4, Size=16
                               * ByteAddr=160
                               */
    ]) :
    new Uint8Array([]);

  var ndef_tlv = new Uint8Array([
    0x03, ndef.length        /* NDEF Message TLV */
  ]);
  var terminator_tlv = new Uint8Array([
    0xfe
  ]);
  var ret = UTIL_concat(tt2_header, 
            UTIL_concat(lock_control_tlv,
            UTIL_concat(ndef_tlv,
            UTIL_concat(new Uint8Array(ndef),
                        terminator_tlv))));
  return ret;
}


// Input:
//   ndef: ArrayBuffer. Just ndef is needed. TT2 header is handled.
TT2.prototype.write = function(device, ndef, cb) {
  if (!cb) cb = defaultCallback;

  var self = this;
  var callback = cb;
  var card = self.compose(new Uint8Array(ndef));
  var card_blknum = Math.floor((card.length + 3) / 4);

  /* TODO: check memory size according to CC value */
  if (card_blknum > (64 / 4)) {
    console.warn("write_tt2() card length: " + card.length +
                 " is larger than 64 bytes. Try to write as Ultralight-C.");
    if (card_blknum > (192 / 4)) {
      console.error("write_tt2() card length: " + card.length +
                    " is larger than 192 bytes (more than Ultralight-C" +
                    " can provide).");
      return callback(0xbbb);
    }
  }

  function write_block(card, block_no) {
    if (block_no >= card_blknum) { return callback(0); }

		var data = card.subarray(block_no * 4, block_no * 4 + 4);
    if (data.length < 4) data = UTIL_concat(data,
                                            new Uint8Array(4 - data.length));

    device.write_block(block_no, data, function(rc) {
      if (rc) return callback(rc);
      write_block(card, block_no + 1);
    });
  }

  /* Start from CC* fields */
  write_block(card, 3);
}


TT2.prototype.emulate = function(device, ndef_obj, timeout, cb) {
  var data = this.compose(new Uint8Array(ndef_obj.compose()));
  return device.emulate_tag(data, timeout, cb);
}
