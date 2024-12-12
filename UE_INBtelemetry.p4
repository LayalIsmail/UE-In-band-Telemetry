/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0X800;
const bit<32> REPORT_MIRROR_SESSION_ID = 500;
const bit<6> IPv4_DSCP_INT = 6w31;   
const bit<16> INT_SHIM_HEADER_LEN_BYTES = 4;
const bit<8> INT_TYPE_HOP_BY_HOP = 1;
const bit<16> HOP_MD_LEN_BYTES = 40;
const bit<5> HOP_MD_WORDS = 10;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<48> ingress_t;
typedef bit<48> egress_t;
typedef bit<32> hoplatency_t;
typedef bit<16> flow_id_t;
typedef bit<16> cpu_t;
typedef bit<32> geo_lalitude_t;
typedef bit<32> geo_longitude_t;
typedef bit<32> geo_altitude_t;
typedef bit<32> antenna_power_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
const bit<16> ETH_HEADER_LEN = 14;

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
const bit<16> IPV4_MIN_HEAD_LEN = 20;

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}
const bit<16> UDP_HEADER_LEN = 8;


header shim_t {
    bit<8> int_type;
    bit<8> rsvd1;
    bit<8> len;    
    bit<6> dscp;  
    bit<2> rsvd3;
}
const bit<16> INT_HEADER_LEN_BYTES = 8;
const bit<4> INT_VERSION = 1;

header int_header_t {
    bit<4>  ver;
    bit<2>  rep;
    bit<1>  c;
    bit<1>  e;
    bit<1>  m;
    bit<7>  rsvd1;
    bit<3>  rsvd2;
    bit<5>  hop_metadata_len;   
    bit<8>  remaining_hop_cnt;  
    bit<16> instruction_mask;
    bit<16> seq;  
}
const bit<16> INT_ALL_HEADER_LEN_BYTES = INT_SHIM_HEADER_LEN_BYTES + INT_HEADER_LEN_BYTES;



header switch_t {
    switchID_t       swid;
    ingress_t        ingress_tstamp;
    egress_t         egress_tstamp;
    hoplatency_t     hop_latency;
    flow_id_t        flow_id;
    cpu_t            cpu_value;
    geo_lalitude_t   geo_lalitude;
    geo_longitude_t  geo_longitude;
    geo_altitude_t geo_altitude; 
    antenna_power_t  antenna_power;
}

header swtraces_t {
    /* 6 nodes * 32 bytes * 8 */
    varbit<1728> swtraces;
}



struct metadata {
    bool isNotClone;
    @field_list(10)
    bit<16>  ingress_port;
    @field_list(10)
    bit<48> ingress_tstamp;
    bit<32> totalllength;             
    @field_list(10)
    bit<8> remaining;
    @field_list(10)
    bit<32> sw_id;
    @field_list(10)
    bool isSink;
    @field_list(10)
    bit<1> source;
    @field_list(10)
    bit<16> fl_id;
    

}

struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    udp_t              udp;
    shim_t             shim;
    int_header_t       int_header;
    switch_t           sw_data;
    swtraces_t         sw_traces; 
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            UDP_PROTOCOL     : parse_udp;
            default          : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.ipv4.dscp) {
            IPv4_DSCP_INT : parse_shim;
            default: accept;
        } }
    
    state parse_shim {
        packet.extract(hdr.shim);
        transition  parse_int;
    }
    
    state parse_int{
    packet.extract(hdr.int_header);
    transition  parse_swtraces;
          

    }

    state parse_swtraces {
        /*
        extraction length = shim total length (including shim header 1 word) - INT hdr (2 words)
        converted from word to bits (left shift by 5 = multiplying by 32 ) 
        */
        packet.extract( hdr.sw_traces,  (bit<32>) ( hdr.shim.len - 3 ) << 5  );
        transition accept;

    }



}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
     
    counter(32w1, CounterType.packets) fwd_counter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<32> sw_id, bit<16> fl_id ) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.sw_id = sw_id;
        meta.fl_id =fl_id;
        if (meta.sw_id == 1) { meta.fl_id = 2;}

    }
    

    action activate_source(bit<8> max_hop ){
        hdr.shim.setValid();
        hdr.shim.int_type = INT_TYPE_HOP_BY_HOP;
        hdr.shim.len = (bit<8>) INT_ALL_HEADER_LEN_BYTES >> 2;
        
        hdr.int_header.setValid();
        hdr.int_header.ver = INT_VERSION;
        hdr.int_header.rep = 0;
        hdr.int_header.c = 0;
        hdr.int_header.e = 0;
        hdr.int_header.m = 0;
        hdr.int_header.rsvd1 = 0;
        hdr.int_header.rsvd2 = 0;
        hdr.int_header.hop_metadata_len = HOP_MD_WORDS;
        hdr.int_header.remaining_hop_cnt = max_hop;  //will be decreased immediately by 1 within transit process
        hdr.int_header.instruction_mask = 0;   
        hdr.shim.dscp = hdr.ipv4.dscp; 
        hdr.ipv4.dscp = IPv4_DSCP_INT;   // indicates that INT header in the packet
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_ALL_HEADER_LEN_BYTES;  // adding size of INT headers
        hdr.udp.length_ = hdr.udp.length_ + INT_ALL_HEADER_LEN_BYTES;  
    }

   

    action configure_sink() {
        meta.isSink = true;   // indicate that INT headers must be removed in egress
        clone_preserving_field_list(CloneType.I2E, REPORT_MIRROR_SESSION_ID, 10); 
        }

    table ipv4_lpm {
        key = {
            
            hdr.ipv4.dstAddr: lpm;
            hdr.udp.dst_port: exact;
          
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table tb_activate_source {
    
        key = {
            standard_metadata.ingress_port: exact;
            hdr.udp.dst_port: exact;
        }
        actions = {
            activate_source;
        }
        size = 255;
    }



    table tb_int_sink {
        actions = {
            configure_sink; NoAction;
        }
        key = {
             standard_metadata.egress_spec: exact;
             hdr.udp.dst_port: exact;
            

        }
        size = 255;
    }

    
    


    apply {

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
           

            meta.ingress_tstamp = standard_metadata.ingress_global_timestamp;
            meta.ingress_port = (bit<16>)standard_metadata.ingress_port;
            tb_activate_source.apply();
            tb_int_sink.apply();
        
            if (meta.isSink){
                configure_sink();
            }
        }
    }
    
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

     register<bit<16>> (1) cpu_register; 
     register<bit<32>> (1) geo_lalitude_register;
     register<bit<32>> (1) geo_longitude_register;
     register<bit<32>> (1) geo_altitude_register;
     register<bit<32>> (1) antenna_power_register;
    
    action add_swtrace() {
        hdr.sw_data.setValid();
        hdr.sw_data.swid = meta.sw_id;
        hdr.sw_data.ingress_tstamp = meta.ingress_tstamp;
        hdr.sw_data.egress_tstamp = (egress_t)standard_metadata.egress_global_timestamp;
        hdr.sw_data.hop_latency = (bit<32>) ( standard_metadata.egress_global_timestamp - meta.ingress_tstamp );
        hdr.sw_data.flow_id = meta.fl_id;
        cpu_register.read(hdr.sw_data.cpu_value,0);
        geo_lalitude_register.read(hdr.sw_data.geo_lalitude,0);
        geo_longitude_register.read(hdr.sw_data.geo_longitude,0);
        geo_altitude_register.read(hdr.sw_data.geo_altitude,0);
        antenna_power_register.read( hdr.sw_data.antenna_power,0);
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen +  HOP_MD_LEN_BYTES;
        hdr.udp.length_ = hdr.udp.length_ + HOP_MD_LEN_BYTES;
        hdr.shim.len = hdr.shim.len + (bit<8>) HOP_MD_WORDS;
        }

    action changeReport_action(macAddr_t dstAddrmac, ip4Addr_t dstAddrip, bit<16> dst_port ){
        hdr.ethernet.dstAddr = dstAddrmac;
        hdr.ipv4.dstAddr = dstAddrip;
        hdr.udp.dst_port = dst_port;
    }    

    table changeReport_table{
    
      key = {
      
            }
      actions = {
            changeReport_action; NoAction;
      }  
     
      }
    
    

    apply {
        
        if (meta.isSink && standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE ){
            
        add_swtrace();
            
          //  IPv4 length = 20 bytes IP header length + 8 bytes udp + 4byte shim 
          
        hdr.ipv4.totalLen = IPV4_MIN_HEAD_LEN + UDP_HEADER_LEN + (bit<16>) (hdr.shim.len << 2) ;
            
        hdr.udp.length_ = UDP_HEADER_LEN + (bit<16>) (hdr.shim.len << 2);
  
        changeReport_table.apply();

        meta.totalllength = (bit<32>) ( ETH_HEADER_LEN + IPV4_MIN_HEAD_LEN + UDP_HEADER_LEN + (bit<16>) (hdr.shim.len << 2)  );
        truncate(meta.totalllength);


        } else {
            if (hdr.shim.isValid() && !(meta.isSink) ){
                add_swtrace();
            }
            if (meta.isSink  && standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL){
                hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>) ( hdr.shim.len << 2 ) ;
                hdr.udp.length_ = hdr.udp.length_ -  (bit<16>) (hdr.shim.len << 2) ;
                hdr.ipv4.dscp =hdr.shim.dscp;
                
                hdr.shim.setInvalid();
                hdr.int_header.setInvalid();
                hdr.sw_traces.setInvalid();

            }
        }


    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.sw_data);
        packet.emit(hdr.sw_traces);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
