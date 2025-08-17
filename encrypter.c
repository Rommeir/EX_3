int main()
{
    char buffer[1024] = {0};
    int pipefd[2] = {0, 0};
    int rc = pipe(pipefd);
    if(rc < 0)
    {
        printf("runtime error: %s", strerror(errno));
        return 0;
    }

    printf("PID: %d\n", getpid());
    printf("Pipe read end: %d\n", pipefd[READ_END]);
    printf("Pipe write end: %d\n", pipefd[WRITE_END]);

    int pid = fork();
    if(pid > 0) // PARENT
    {
        bool endOpCode = false;
        close(pipefd[WRITE_END]); 
        while(endOpCode == false){
            TLV* tlv = readTlvFromPipe(pipefd[READ_END]);
            
            switch (tlv->type)
            {
            case TEXT_OP_CODE:
                printf("Type: %d\n", tlv->type);
                printf("Length: %d\n", tlv->length);
                printf("Value: %s\n", tlv->value);
                break;
            case END_OP_CODE:
                printf("Exiting\n");
                exit(0);
            default:
                break;
            }

            delete(tlv); 
        }
    }
    else if(pid == 0) // CHILD
    {
        int len = -1;
        close(pipefd[READ_END]); 

        TLV tlv = {TEXT_OP_CODE, 5, "hello"};
        writeTlvToPipe(pipefd[WRITE_END], &tlv);

        tlv = {TEXT_OP_CODE, 5, "world"};
        writeTlvToPipe(pipefd[WRITE_END], &tlv);

        tlv = {END_OP_CODE, 0, "\0"};
        writeTlvToPipe(pipefd[WRITE_END], &tlv);
    }

    return 0;
}
