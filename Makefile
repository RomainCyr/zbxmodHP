zbxmodHP-2.2: zbxmodHP-2.2.c
	gcc -shared -o zbxmodHP.so zbxmodHP-2.2.c -I../include -fPIC
zbxmodHP-3.0: zbxmodHP-3.0.c
	gcc -shared -o zbxmodHP.so zbxmodHP-3.0.c -I../include -fPIC -lsnmp
zbxmodHP-3.2: zbxmodHP-3.2.c
	gcc -shared -o zbxmodHP.so zbxmodHP-3.2.c -I../include -fPIC -lsnmp
