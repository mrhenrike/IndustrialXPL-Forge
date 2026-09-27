        char *replace(const char *s)
        {
            size_t i, j;
            size_t len, extra;
            char *r = NULL;
        
            len = strlen(s);
            extra = 0;
        
            /* First we count how much extra space we need */
            for (i = 0; i < len; ++i) {
                if (s[i] == '<')
                    extra += strlen("\n") - 1; 
            }
        
            /* Allocate a new string with the extra space */
            r = malloc(len + extra + 1);
            assert(r != NULL);
        
            /* Put in the extra characters */
            j = 0;
            for (i = 0; i < len; ++i) {
                if (s[i] == '<') {
                    r[j++] = '\n';
                    i = i + 3; /* skip rest of br> */
                } else {
                    r[j++] = s[i];
                }
            }
        
            /* Mark the end of the new string */
            r[j] = '\0';
        
            return r;
        }
