# SPDX-License-Identifier: GPL-3.0-only WITH NVIDIA-integration-exception
# GP106 constructors/getters derived from SupraGSX, pinned commit in NOTICE.txt.
# No tracing, event logging, forced stops, timer interception or FIFO bypass.
.intel_syntax noprefix
.code32
.section .text
.macro delta reg
 call 991f
991: pop \reg
 sub \reg, offset 991b
.endm
.global clean_begin,clean_end,clean_code_end
clean_begin:

.global gp106_fecs
gp106_fecs:
 push ebx
 push esi
 mov esi,[esp+16]
 push esi
 push dword ptr [esp+16]
 call original_gp106_fecs
 push eax
 delta ebx
 lea eax,[ebx+get_fecs_signature]
 mov [esi+0x28],eax
 lea eax,[ebx+get_fecs_boot]
 mov [esi+0x34],eax
 lea eax,[ebx+get_fecs_header]
 mov [esi+0x38],eax
 pop eax
 pop esi
 pop ebx
 ret 8
.global gp106_gpccs
gp106_gpccs:
 push ebx
 push esi
 mov esi,[esp+16]
 push esi
 push dword ptr [esp+16]
 call original_gp106_gpccs
 push eax
 delta ebx
 lea eax,[ebx+get_gpccs_signature]
 mov [esi+0x24],eax
 lea eax,[ebx+get_gpccs_boot]
 mov [esi+0x30],eax
 lea eax,[ebx+get_gpccs_header]
 mov [esi+0x34],eax
 pop eax
 pop esi
 pop ebx
 ret 8
.global gp106_gr
gp106_gr:
 push ebx
 push esi
 mov esi,[esp+16]
 push esi
 push dword ptr [esp+16]
 call original_gp106_gr
 push eax
 delta ebx
 lea eax,[ebx+get_gr_bundle]
 mov [esi+0x3e4],eax
 pop eax
 pop esi
 pop ebx
 ret 8

# Only fifth comparison: original equality OR actual 12 / expected 15.
# Preserve the original first four comparisons and strict sixth comparison.
.global accept_region
accept_region:
 mov ecx,[esp+0x14]
 push eax
 mov eax,[edi]
 cmp ecx,eax
 je .Lregion_accept
 cmp ecx,12
 jne .Lregion_reject
 cmp eax,15
 jne .Lregion_reject
.Lregion_accept:
 pop eax
 jmp region_continue
.Lregion_reject:
 pop eax
 jmp region_reject

# Reproduce Driver 68/69's bounded 76->84 conversion, without telemetry.
# The donor GP106 providers require two zero tail dwords (argc and argv).
.global gr_descriptor
gr_descriptor:
 pushfd
 pushad
 mov ebp,edi
 delta eax
 cmp dword ptr [ebp+4],2
 je .Lfecs
 cmp dword ptr [ebp+4],3
 jne .Loriginal
 lea edi,[eax+gpccs_signature_payload]
 jmp .Lsignature
.Lfecs:
 lea edi,[eax+fecs_signature_payload]
.Lsignature:
 lea esi,[ebp+0x1c]
 mov ecx,48
 cld
 repe cmpsd
 jne .Loriginal
 cmp dword ptr [ebp+0x158],76
 jne .Lbad
 cmp dword ptr [ebp+0xf4],84
 jb .Lbad
 test ebx,ebx
 jz .Lbad
 popad
 popfd
 sub esp,84
 push esi
 push edi
 lea esi,[edi+0x10c]
 lea edi,[esp+8]
 mov ecx,19
 cld
 rep movsd
 xor eax,eax
 stosd
 stosd
 pop edi
 pop esi
 mov edx,esp
 push 84
 push edx
 push ebx
 call previous_copy
 add esp,84
 jmp after_copy
.Loriginal:
 popad
 popfd
 mov ecx,[edi+0x158]
 jmp original_arguments
.Lbad:
 popad
 popfd
 mov ebx,0x57
 jmp native_failure

.macro resource role, bytesize
.global get_\role,\role\()_descriptor
get_\role:
 delta eax
 lea edx,[eax+\role\()_payload]
 mov [eax+\role\()_descriptor+4],edx
 lea eax,[eax+\role\()_descriptor]
 ret 4
.balign 4,0
\role\()_descriptor: .long \bytesize,0,0
.endm
resource fecs_signature,192
resource gpccs_signature,192
resource gr_bundle,90288
resource fecs_boot,512
resource fecs_header,24
resource gpccs_boot,512
resource gpccs_header,24
clean_code_end:
.org 1024,0
clean_end:
