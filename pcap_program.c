#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <ctype.h>
int counter=0;  //stores total number of unique ip addresses
int map(char* ipaddr,int ipnum);  //stores the ip address and the corresponding number mapped to it.
void edge(int ipvalue);           //stores interacting ip address numbers and their duration of interaction.  

int main() 
{ 
  int retmap=0;    //return value of function map
  int ts_sec1=0,ts_usec1=0,ts_sec2=0,ts_usec2=0;  //stores time in sec and microseconds of the current packet and preveious packet.
  int diff=0,udiff=0;  //difference between the time of both packets in seconds and microseconds  
  FILE *ifile1;
 
  struct pcap_pkthdr header; // The header that pcap gives us 
  const u_char *pkt_ptr; // The actual packet 
  pcap_t *handle;  
  char errbuf[PCAP_ERRBUF_SIZE]; 
  struct in_addr ipsrc;  //source ip address of the current packet
  struct in_addr ipdst;  //destination ip address of the current packet
   
  handle = pcap_open_offline("/home/hp/Desktop/tcpdump/packets.pcap", errbuf);   //call pcap library function 
  if (handle == NULL)
    { printf("Couldn't open pcap file: %s\n",errbuf); 
      return(2); 
    } 
    // printf("file opened \n");
  
  while((pkt_ptr = pcap_next(handle,&header))!=NULL)
   {  
    ts_sec2 = header.ts.tv_sec;
    ts_usec2 = header.ts.tv_usec;
         
    //parse the IP header 
    pkt_ptr +=14;  //skip past the Ethernet header with offset of 14 assuming ethernet type = IP
    struct ip *ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure
     
    if(ts_usec1!=0 && ts_sec1!=0)      //if its not the first packet,print the time difference first and then call functions map and edges.
    { 
       if(ts_usec2>ts_usec1)
       { udiff=ts_usec2-ts_usec1;
         diff=ts_sec2-ts_sec1;
       }
       else if(ts_usec2<ts_usec1)
       {  udiff=(1000000 - ts_usec1) + ts_usec2;
          diff=(ts_sec2-ts_sec1);
       }
       else
       {  diff=ts_sec2-ts_sec1;
          udiff=0;
       }
      
       ifile1=fopen("/home/hp/Desktop/tcpdump/edges.txt","a+");  //open the edges file, print the time and go the next line.
       if(ifile1==NULL)
       printf("edge in main first loop file not opened\n");
       //  else
       //printf("file opened\n");
       fprintf(ifile1,"   %d sec %d usec \n",diff,udiff);
       fputc('\n',ifile1);
       fclose(ifile1);

       ipsrc=ip_hdr->ip_src; 
       char *ip1=inet_ntoa(ipsrc);
      
       retmap=map(ip1,counter);
       edge(retmap);
       
       ipdst=ip_hdr->ip_dst;
       char *ip2=inet_ntoa(ipdst);
      
       retmap=map(ip2,counter);
       edge(retmap);
   }  

   if(ts_usec1==0 && ts_sec1==0) //if its the first packet,call functions first.
   {  
      ipsrc=ip_hdr->ip_src; 
      char *ip1=inet_ntoa(ipsrc);

      retmap=map(ip1,counter);
      edge(retmap);

      ipdst=ip_hdr->ip_dst;
      char *ip2=inet_ntoa(ipdst);

      retmap=map(ip2,counter);
      edge(retmap);
   } 
  
   ts_sec1 = header.ts.tv_sec; 
   ts_usec1 = header.ts.tv_usec;
  
  
 }
 pcap_close(handle);  //close the pcap file 

} //end of main() function

int map(char* ipaddr,int ipnum)
{ 
   FILE *ifile;
   int space=0;int len=0,i=0;
   struct map1 
   { char ip[15];
     int num;
   }; struct map1 m;

   ifile = fopen("/home/hp/Desktop/tcpdump/map.txt","a+");
   if(ifile == NULL)
   printf("map file not opened\n");
   //else
   //printf("file opened\n");

   while((fscanf(ifile, "%s %d", m.ip, &m.num )) !=EOF) //to check if ip address is already mapped to some number
    { 
        if((strcmp(m.ip,ipaddr))==0)
        { 
         return m.num;
	}
    }
  
   counter=counter+1;
   
   len=strlen(ipaddr);
   if(len<15)
   { space = 15-len;
   }
   
   fprintf(ifile,"%s",ipaddr);
   
   while(i<=space) //for adjusting the spaces properly 
   {fputc(' ',ifile);
    i++;
   }
   fprintf(ifile,"  %d",ipnum+1);
   fputc('\n',ifile);
     
   fclose(ifile);
   return ipnum+1;
}  //end of map()   

void edge(int ipvalue)
{
   FILE *ifile1;
 
   ifile1=fopen("/home/hp/Desktop/tcpdump/edges.txt","a+");
   if(ifile1==NULL)
   printf("edge file not opened\n");
   //else
   //printf("file opened\n");

   fprintf(ifile1,"%d ",ipvalue);
   
   fclose(ifile1);
} //end of edge()


