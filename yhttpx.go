package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// options
type Options struct {
	InputFile string
	SingleTarget string
	threads   int
	timeout   int
}

var options *Options
const symbol_for_stdio = "std.io.placehoder"

func parse_options() *Options {
	options := &Options{}
	flag.StringVar(&options.InputFile, "i", symbol_for_stdio, "file contains url stirngs /input can be from os.stdin or pipe")
	flag.StringVar(&options.SingleTarget, "d", "", "single domain name to be detect. (ip|domain)[:port]")
	flag.IntVar(&options.threads, "t", 50, "limit concurrent threads num")
	flag.IntVar(&options.timeout, "w", 6, "timeout seconds")
	flag.Usage= func() {
		fmt.Println(`
>===========================================================<
>              _                                            <
>             | |     _     _                               <
>        _   _| |__ _| |_ _| |_ ____ _   _                  <
>       | | | |  _ (_   _|_   _)  _ ( \ / )                 <
>       | |_| | | | || |_  | |_| |_| ) X (                  <
>        \__  |_| |_| \__)  \__)  __(_/ \_)                 <
>       (____/                 |_|  		@afwu    <
>                                                           <
>       yhttpx: fastly identify http[s] service             <
>===========================================================<
common usage:
	yhttpx -d qq.com
	echo qq.com:443 | yhttpx
	yhttpx -i ip.txt -t 100 -w 10
	yhttpx -h

common params:`)
		flag.PrintDefaults()
	}
	flag.Parse()

	return options
}


func check_https(ip_port string)string{
	if !strings.Contains(ip_port,":"){ip_port+=":443"}
	server_hello_fingerprint:="16030300" // maybe 15030300xxxxx

	//https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art059
	//https://golang.org/src/crypto/tls/handshake_client.go
	//https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.2
	client_hello_demo:="160301006b010000670303ec12dd1764a439fd7e8c8546b84d1ea06eb3d7a051f03cb817470d4c54c5df7200003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff01000000"

	client_hello_to_request_ssl_context,_:=hex.DecodeString(client_hello_demo)

	conn,err:=net.DialTimeout("tcp",ip_port,time.Duration(options.timeout/2)*time.Second)
	if err!=nil{return "timeout"}
	conn.Write(client_hello_to_request_ssl_context)
	server_hello_bytes:=make([]byte,4)
	conn.Read(server_hello_bytes)
	server_hello:=hex.EncodeToString(server_hello_bytes)

	if server_hello_fingerprint  == server_hello {
		return "https"
	}else {
		return "unknown"
	}
}


func check_http(ip_port string)string{
	if !strings.Contains(ip_port,":"){ip_port+=":80"}
		server_hello_fingerprint:=hex.EncodeToString([]byte("HTTP"))
	client_hello_demo:=`GET / HTTP/1.1
Host: www.baidu.com
Accept-Encoding: *
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36
Connection: close

`

	conn,err:=net.DialTimeout("tcp",ip_port,time.Duration(options.timeout/2)*time.Second)
	if err!=nil{
		return "timeout"
	}
	client_hello:=strings.Replace(client_hello_demo,"Host: www.baidu.com","Host: "+strings.Split(ip_port,":")[0],1)
	conn.Write([]byte(client_hello))

	server_hello_bytes:=make([]byte,4)
	conn.Read(server_hello_bytes)
	server_hello:=hex.EncodeToString(server_hello_bytes)

	if server_hello_fingerprint  == server_hello{
			return "http"
	}else {
		return "unknown"
	}
}

func touch(ip_port string)  {
	ip_port=regexp.MustCompile("(^\\s+|\\s+$)").ReplaceAllString(ip_port,"") // strip leading and following spaces
	if "https"==check_https(ip_port){
		fmt.Println(regexp.MustCompile(":443$").ReplaceAllString("https://"+ip_port,"")) // strip following :443
	}else {
		if "http"==check_http(ip_port){
			fmt.Println(regexp.MustCompile(":80$").ReplaceAllString("http://"+ip_port,"")) // strip following :80
		}
	}
}

func multi_thread()  {
	if len(options.SingleTarget)!=0{
		touch(options.SingleTarget)
		return
	}

	var wg sync.WaitGroup
	var ch = make(chan struct{}, options.threads)
	var f1 io.Reader
	if options.InputFile==symbol_for_stdio{f1=os.Stdin}else{f1,_=os.Open(options.InputFile) /* url*/}
	sc:=bufio.NewScanner(f1)
	for sc.Scan(){
		ip_port:=regexp.MustCompile("(^\\s+|\\s+$)").ReplaceAllString(sc.Text(),"") // strip leading and following spaces
		wg.Add(1)
		ch <- struct{}{} // acquire a token
		go func(single_ip_port string) {
			defer wg.Done()
			touch(single_ip_port)
			<-ch // release the token
		}(ip_port)
	}
	wg.Wait()
}

func main()  {
	options=parse_options()
	multi_thread()
}
