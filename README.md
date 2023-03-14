# py-process-patch

## About
A set of tools to facilitate patching the memory of processes running on Windows for 
modifying their behavior or extending their capabilities.

## Features
* <b>Declarative patching</b><br/>
   Define patches to perform on the process with ease using a configuration file in YAML format.
   Modify process memory and inject code into the process.
* <b>Copy memory</b><br/>
   Create copies of memory regions within the target process. This is useful for bypassing memory integrity checks.
* <b>Read & Analyze</b><br/>
   Read and analyze data read from a process.

## Getting started
```
git clone https://github.com/davidjoseph9/py-process-patch.git ./py-process-patch
cd ./py-process-patch
pip install .
```

The following is an exampl
```yaml
name: Sample Game patches
architecture: x86
mode: 64
description: |
  Sample game patches to demonstrate the features of the py-process-patch module
processes:
- name: NotMS.exe
  virtual_alloc: 128Kb  # Allocate pages of memory to store code caves and pointers in
  wait_for_process: true
  copies:
  - name: MapleStoryRegionCopy
    size: 0x4800000
    src_address: 0x140001000
  - name: NGClient64Copy
    module: NGClient64.aes
    size: 0xBDA000
  patch_groups:
  - name: Bypass
    patches:
    - name: Memory integrity check bypass
      enable: true
      patch_type: hook
      hook_type: jump
      address: 0x1484C5BE5
      vars:
        region_start: 0x140001000
      alloc_vars:  # uses memory allocated at the start
        return_address: 
          size: 8
          value: 0x1484C5C05
      asm: |
        pop rbx
        push rsi
        push rdi
        push rcx
        mov rcx, rax
        mov rsi, {{ copy_map.MapleStoryRegionCopy.address | hex }}
        mov rdi, [rsp+0x28]
        repe movsb
        pop rcx
        pop rdi
        pop rsi
        sub rsp, 0x08
        push r12
        mov r12, rbp
        push rbp
        mov rbp, r12
        mov [rsp+0x10], rbp
        pop rbp
        mov r12, [rsp]
        add rsp, 0x08
        mov rbx, 
        mov rbx, {{ return_address | hex }}
        jmp rbx
```

```yaml
- name: BlackCipher64.aes
  virtual_alloc: 128Kb  # Allocate pages of memory to store code caves and pointers in
  wait_for_process: true
  copies:
  - name: BlackCipher64Copy
    module: BlackCipher64.aes
    size: 0x4E8E000
  - name: BCLib1Copy
    size: 0x214000
    pointer:
      module: "ntdll.dll"
      offset: 0x199570
  - name: BCLib2Copy
    size: 0x39C000
    pointer:
      module: "ntdll.dll"
      offset: 0x199558
  patch_groups:
  - name: Bypass - MIC and NGS
    patches:
    - name: Bypass memory integrity check
      description: Memory integrity check bypass for BlackCipher64.aes and BC7F9A.tmp modules
      enable: true
      patch_type: hook
      hook_type: jump
      module: BlackCipher64.aes
      offset: 0xEA6B7
      vars:
        return_offset: 0xEA6C4
      asm: |
        pop ebx
        mov rax, [rsp+0x20]
  
        _BlackCipherCheck:
        mov rbx, {{ copy_map.BlackCipher64Copy.src_address | hex }}
        cmp rax, rbx
        jb _MICPrimaryOriginal
        cmp rax, {{ format_address(copy_map.BlackCipher64Copy.src_address, copy_map.BlackCipher64Copy.size) }}
        jg _MICPrimaryOriginal
        mov rbx, {{ copy_map.BCLib1Copy.src_address | hex }}
        cmp rax, rbx
        jb _MICPrimaryOriginal
        mov rbx, {{ format_address(copy_map.BCLib1Copy.src_address, copy_map.BCLib1Copy.size) }}
        cmp rax, rbx
        jg _MICPrimaryOriginal
        mov rbx, {{ copy_map.BCLib1Copy.src_address | hex }}
        sub rax, rbx
        add rax, {{ copy_map.BlackCipher64Copy.address | hex }}
  
        _MICPrimaryOriginal:
        mov rax,[rax]
        mov eax,[rax]
        mov ecx,[rsp]
        mov rbx, {{ format_address(module_map[module].start_address, return_offset) }}
        jmp rbx
```