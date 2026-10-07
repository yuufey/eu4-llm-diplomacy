static wchar_t popup_request[MAX_PATH];
static void popup_control_tick() {
    HANDLE file=CreateFileW(popup_request,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if (file==INVALID_HANDLE_VALUE) return;
    char content[160]{}; DWORD got=0,size=GetFileSize(file,nullptr);
    bool valid=size<sizeof(content) && ReadFile(file,content,size,&got,nullptr) && got==size;
    CloseHandle(file);
    if (!DeleteFileW(popup_request) || !valid) return;
    unsigned long pid=0; unsigned long long object=0,button=0,owner=0; int consumed=0;
    valid=sscanf(content,"TEST_ONLY %lu %llx %llx %llx%n",&pid,&object,&button,&owner,&consumed)==4
        && strcmp(content+consumed,"\n")==0 && pid==GetCurrentProcessId();
    uintptr_t vt=0,widget=0,node=0,first=0,second=0,next=0,first_owner=0,first_callback=0,second_owner=0,second_callback=0;
    unsigned char closed=1; uint64_t size_name=0;
    char name[16]{}; SIZE_T read_size=0;
    valid=valid && read(object,vt) && vt==base+0x1d57328 && read(object+8,widget) && widget
        && read(object+0x114,closed) && !closed && read(object+0x128,size_name) && size_name==14
        && ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(object+0x118),name,15,&read_size)
        && read_size==15 && strcmp(name,"DefaultConfirm")==0
        && read(button,vt) && vt==base+0x1d58510 && read(button+0xd0,node)
        && read(node,first) && first==object+0x18 && read(node+0x10,next)
        && read(next,second) && read(next+0x10,node) && node==0
        && read(first+8,first_owner) && first_owner==object
        && read(first+16,first_callback) && first_callback==base+0x10a0e18
        && read(second+8,second_owner) && second_owner==owner
        && read(second+16,second_callback) && second_callback==base+0x10ef2e0;
    if (!valid) { line("{\"event\":\"popup_confirmation_rejected\"}\n"); return; }
    line("{\"event\":\"popup_confirmation_begin\",\"callbacks\":[\"0x10a0e18\",\"0x10ef2e0\"]}\n");
    using Callback=void (*)(void*);
    control_pause_after_load=true;
    control_load_wait_frames=2;
    reinterpret_cast<Callback>(first_callback)(reinterpret_cast<void*>(first_owner));
    reinterpret_cast<Callback>(second_callback)(reinterpret_cast<void*>(second_owner));
    line("{\"event\":\"popup_confirmation_callbacks_returned\"}\n");
}
