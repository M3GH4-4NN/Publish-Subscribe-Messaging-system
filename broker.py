import socket
import threading
import json
import sys

HOST = "0.0.0.0"   # listen on all interfaces
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

topics = {}                 #set of subscriber socks, format : {A: {smth1,smth2},B:{smthelse}} -> dict of sets
lock = threading.Lock()     #lets only 1 thread edit topics at a time


def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode()) 
    #sendall sends everything to socket,json just provides the formatting, .encode() converts stuff to binary



def remove_client(conn):
    """Remove a disconnected client/subscriber? from every topic."""
    with lock:  #lock mentioned here so only 1 broker edits it at a time
        for subs in topics.values():
            subs.discard(conn) #removes the socket (wont crash if conn = socketname is not there)


def process(conn, msg, addr): #we get a dictionary for the msg
    mtype = msg.get("type") #takes out the type of msg (SUBSCRIBE,UNSUBSCRIBE,PUBLISH) like http requst types
    topic = msg.get("topic") #same but for the topic (based on what were storing)

    if mtype == "SUBSCRIBE" and topic:
        with lock:
            topics.setdefault(topic, set()).add(conn) #finds topic:{smth1,smth2} and adds con(socket) to the set
							#if the socket already exists it wont make a difference
        send_json(conn, {"type": "ACK", "info": f"subscribed to {topic}"}) #sends ACK to socket
        print(f"[SUB]   {addr} -> {topic}")
	#basically just added a socket to the topics (added dubscriber to list of subscribers for the publisher)

    elif mtype == "UNSUBSCRIBE" and topic: #this whole thing just removes a socket from topics 
        with lock:
            topics.get(topic, set()).discard(conn)
        send_json(conn, {"type": "ACK", "info": f"unsubscribed from {topic}"})
        print(f"[UNSUB] {addr} -> {topic}")

    elif mtype == "PUBLISH" and topic: #actual data transfer-------------------------
        delivered = 0 #initially set
        with lock:
            for sub in list(topics.get(topic, set())): #to send the msg to all subscribers
                try: #the format for each message is defined here
                    send_json(sub, { #changes the type of msg coming from publisher from PUBLISH to MESSAGE
                        "type": "MESSAGE",
                        "topic": topic,
                        "payload": msg.get("payload"),
                        "seq": msg.get("seq"),
                        "ts": msg.get("ts"),
                    })
                    delivered += 1 #counts the no of msgs sent IDK why required -------------
                except OSError: #will happen only if socket was closed or unsubscribed
                    topics[topic].discard(sub)   # dead subscriber
        print(f"[PUB]   {addr} topic={topic} seq={msg.get('seq')} delivered to {delivered}")


def handle_client(conn, addr):  #we run a thread for this function
    print(f"[+] connected: {addr}")
    buf = ""  #empty buffer at the start
    try:
        while True:
            data = conn.recv(4096) #it check 4096 bytes for data on the socket , data will be in json format
            if not data: #if no data was found on the socket then it stops the execution
                break
            buf += data.decode() #else it will decode the data (it was in binary form) and put it in buffer
            while "\n" in buf:              # one JSON message per line
                line, buf = buf.split("\n", 1) #each entry into the socket is separated with newline
                if not line.strip(): #removes whitespaces
                    continue
                try:
                    msg = json.loads(line) #changes json format to python readable format and stores msg
                except json.JSONDecodeError:
                    continue
                process(conn, msg, addr) #calls the processing part
    except (ConnectionResetError, OSError): #if no subscribers
        pass
    finally:
        remove_client(conn) 
        conn.close()
        print(f"[-] disconnected: {addr}")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates TCP socket
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #???----------------------------------
    server.bind((HOST, PORT)) #attaches socket to the IP addr and the port 
    server.listen() #waits for incoming connections
    print(f"Broker listening on port {PORT}") #just a check
    while True:
        conn, addr = server.accept() #when server.listen gets a connection this returns the new socket and ip	
	#server is still listenning for other connections
        # one thread per client = concurrent connections
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()  
	#makes thread for handle_client , puts arguments for conn = socket and addr = ip 
	#daemon = True kills thread as soon as main ends


if __name__ == "__main__":
    main()
