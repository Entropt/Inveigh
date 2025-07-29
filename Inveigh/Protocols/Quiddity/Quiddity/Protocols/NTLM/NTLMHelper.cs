/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2024, Kevin Robertson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
using System;
using Quiddity.SPNEGO;
using Quiddity.Support;
using System.IO;
using System.Text;

namespace Quiddity.NTLM
{
    class NTLMHelper
    {
        public string Signature { get; set; }
        public uint MessageType { get; set; }

        public NTLMHelper()
        {

        }
        public NTLMHelper(byte[]data)
        {
            if (data == null || data.Length == 0)
            {
                return;
            }

            string signature = Encoding.UTF8.GetString(data, 0, Math.Min(8, data.Length));

            if (signature.StartsWith("NTLMSSP"))
            {
                ReadBytes(data, 0);
            }
            else
            {
                try
                {
                    SPNEGONegTokenInit token = this.Decode(data);
                    if (token.MechToken != null && token.MechToken.Length > 0)
                    {
                        this.ReadBytes(token.MechToken, 0);
                    }
                }
                catch (Exception)
                {
                    // Handle malformed SPNEGO tokens gracefully
                    this.Signature = string.Empty;
                    this.MessageType = 0;
                }
            }
        }

        public NTLMHelper(byte[] data, int offset)
        {
            ReadBytes(data, offset);
        }

        public void ReadBytes(byte[] data, int offset)
        {
            // Check if we have enough data to read the minimum NTLM header (8 bytes signature + 2 bytes message type)
            if (data == null || data.Length < offset + 10)
            {
                this.Signature = string.Empty;
                this.MessageType = 0;
                return;
            }

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = offset;
                
                try
                {
                    this.Signature = Encoding.UTF8.GetString(packetReader.ReadBytes(8));
                    this.MessageType = packetReader.ReadUInt16();
                }
                catch (EndOfStreamException)
                {
                    // Handle the case where stream is shorter than expected
                    this.Signature = string.Empty;
                    this.MessageType = 0;
                }
            }

        }

        private SPNEGONegTokenInit Decode(byte[] data)
        {
            SPNEGONegTokenInit spnegoNegTokenInit = new SPNEGONegTokenInit
            {
                MechTypes = ASN1.GetTagBytes(6, data),
                MechToken = ASN1.GetTagBytes(4, data)
            };

            return spnegoNegTokenInit;
        }

    }

}
