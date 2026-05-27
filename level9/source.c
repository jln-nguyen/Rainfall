#include <cstring>
#include <cstdlib>

class N
{
public:
    char    data[104];
    int     value;

    N(int val) : value(val) {}

    virtual void operator+(N &other) {}
    virtual void operator-(N &other) {}

    void setAnnotation(char *str)
    {
        memcpy(data, str, strlen(str));
    }
};

int main(int argc, char **argv)
{
    if (argc < 2)
        _exit(1);

    N *obj1 = new N(5);
    N *obj2 = new N(6);

    obj1->setAnnotation(argv[1]);

    *obj2 + *obj1;

    return 0;
}
