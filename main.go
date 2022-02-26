package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/fastnetmon/fastnetmon_flowlogs_lambda/fastnetmon"
	capnp "zombiezen.com/go/capnproto2"
)

var interface_info map[string]InterfaceDetails
var interface_info_mutex sync.RWMutex
var rewrite_internal_ip_to_external = false

// It will be started just once, as for normal Go app: https://docs.aws.amazon.com/lambda/latest/dg/golang-handler.html
func init() {
	fmt.Printf("Run lambda init logic\n")

	if os.Getenv("fastnetmon_rewrite_internal_to_external_ip") != "" {
		rewrite_internal_ip_to_external = true

		fmt.Printf("Loading IP mapping for the first time\n")
		load_ip_mapping()
		fmt.Printf("Initial mapping loading finished\n")
	} else {
		fmt.Printf("IP mapping logic is not enabled. Please set fastnetmon_rewrite_internal_to_external_ip to true to enable it")
	}
}

func update_ip_mapping() {
	// Set write lock
	interface_info_mutex.Lock()
	defer interface_info_mutex.Unlock()

	load_ip_mapping()
}

func load_ip_mapping() {
	aws_region := os.Getenv("AWS_REGION")

	fmt.Printf("AWS region: %s\n", aws_region)

	var err error

	fmt.Printf("Loading interface and IP address mapping\n")
	interface_info, err = get_external_ip_for_interface(aws_region)

	if err != nil {
		fmt.Printf("Cannot retrieve interface info with error: %v\n", err)
	} else {
		fmt.Printf("Loaded mapping table with %d elements\n", len(interface_info))
		fmt.Printf("Mapping table content: %+v\n", interface_info)
	}

}

// Flow logs format:
// https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-logs-default
// 2 529872196493 eni-09e6d0ed25a626f91 203.216.183.214 172.31.30.120 7010 3389 6 3 152 1586539925 1586539965 REJECT OK
// <version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport> <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>

func handler(ctx context.Context, logsEvent events.CloudwatchLogsEvent) {
	fastnetmon_server_address := os.Getenv("fastnetmon_server_address")

	if fastnetmon_server_address == "" {
		fmt.Print("Please set environment variable fastnetmon_server_address to IP:port format")
		return
	}

	fmt.Printf("Will export data to %s\n", fastnetmon_server_address)

	s, err := net.ResolveUDPAddr("udp4", fastnetmon_server_address)

	if err != nil {
		fmt.Printf("Cannot resolve address: %v\n", err)
		return
	}

	client, err := net.DialUDP("udp4", nil, s)

	if err != nil {
		fmt.Printf("Cannot dial address: %v\n", err)
		return
	}

	data, _ := logsEvent.AWSLogs.Parse()
	for _, logEvent := range data.LogEvents {
		flow_log, err := decode_vpc_flow_log(logEvent.Message)

		if err != nil {
			fmt.Printf("Cannot decode message: %v\n", err)
			continue
		}

		fmt.Printf("Decoded log message from '%v' to '%+v'\n", logEvent.Message, flow_log)

		if rewrite_internal_ip_to_external {
			current_interface_info := get_interface_info(flow_log.Interface)

			if current_interface_info != nil {
				fmt.Printf("Successfully retrieved interface information: %+v\n", current_interface_info)

				// Rewrite IP addresses
				if flow_log.Src_ip.Equal(current_interface_info.InternalIP) {
					flow_log.Src_ip = current_interface_info.ExternalIP
				}

				if flow_log.Dst_ip.Equal(current_interface_info.InternalIP) {
					flow_log.Dst_ip = current_interface_info.ExternalIP
				}

				fmt.Printf("Flow log with external IP addresses: %+v\n", flow_log)
			} else {
				fmt.Printf("Cannot retrieve interface information for %s\n", flow_log.Interface)
			}
		}

		err = flow_log_into_capnp(flow_log, client)

		if err != nil {
			fmt.Printf("Cannot send capnp message: %v\n", err)
			continue
		}
	}

}

// It convers into little endian represenataion
// We use little endian in tera flow
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

func main() {
	if rewrite_internal_ip_to_external {
		go func() {
			ticker := time.NewTicker(60 * time.Second)

			for _ = range ticker.C {
				fmt.Printf("Do scheduled update IP mapping information\n")
				update_ip_mapping()
			}
		}()
	}

	lambda.Start(handler)
}

type VPCFlowLog struct {
	Src_ip           net.IP
	Dst_ip           net.IP
	Src_port         uint16
	Dst_port         uint16
	Protocol         uint32
	Protocol_version uint8
	Packets          uint64
	Bytes            uint64
	Duration         int64
	Interface        string
}

// Decodes VPS Flow logs encoded as string into our intrenal representation
func decode_vpc_flow_log(message string) (*VPCFlowLog, error) {
	list := strings.Split(message, " ")

	flow_log := &VPCFlowLog{}

	// fmt.Printf("Message = %s\n", logEvent.Message)
	version := list[0]
	account_id := list[1]
	interface_id := list[2]

	src_addr := list[3]
	dst_addr := list[4]
	src_port := list[5]
	dst_port := list[6]

	protocol := list[7]
	packets := list[8]
	bytes := list[9]
	flow_start := list[10]
	flow_end := list[11]

	action := list[12]
	log_status := list[13]

	_ = version
	_ = account_id
	_ = action
	_ = log_status

	// fmt.Printf("Version: %s account_id: %s interface id: %s src_addr: %s dst_addr: %s src_port: %s dst_port %s protocol %s packets %s bytes %s start %s end %s action %s log_status %s", version, account_id, interface_id, src_addr, dst_addr, src_port, dst_port, protocol, packets, bytes, start, end, action, log_status)

	src_ip := net.ParseIP(src_addr)

	// Return when we cannot parse
	if src_ip == nil {
		return nil, fmt.Errorf("Cannot decode source ip: %v", src_addr)
	}

	// Ignore IPv6 for now
	if src_ip.To4() == nil {
		return nil, fmt.Errorf("Source IP is not IPv4: %v", src_addr)
	}

	flow_log.Src_ip = src_ip

	dst_ip := net.ParseIP(dst_addr)

	// Skip when we cannot parse IP
	if dst_ip == nil {
		return nil, fmt.Errorf("Cannot decode destination IP: %v", dst_addr)
	}

	// Ignore IPv6
	if dst_ip.To4() == nil {
		return nil, fmt.Errorf("Destionation IP is not IPv4: %v", dst_addr)
	}

	flow_log.Interface = interface_id

	flow_log.Dst_ip = dst_ip

	src_port_number, err := strconv.Atoi(src_port)

	if err != nil {
		return nil, fmt.Errorf("Cannot decode source port: %w")
	}

	flow_log.Src_port = uint16(src_port_number)

	dst_port_number, err := strconv.Atoi(dst_port)

	if err != nil {
		return nil, fmt.Errorf("Cannot decode destination port: %w")
	}

	flow_log.Dst_port = uint16(dst_port_number)

	protocol_number, err := strconv.Atoi(protocol)

	if err != nil {
		return nil, fmt.Errorf("Cannot decode protocol: %w", err)
	}

	flow_log.Protocol = uint32(protocol_number)

	bytes_number, err := strconv.ParseInt(bytes, 10, 64)

	if err != nil {
		return nil, fmt.Errorf("Cannot decode bytes: %w", err)
	}

	flow_log.Bytes = uint64(bytes_number)

	packets_number, err := strconv.ParseInt(packets, 10, 64)

	if err != nil {
		return nil, fmt.Errorf("Cannot decode packets: %w", err)
	}

	// Decode flow duration
	flow_start_int, err := strconv.ParseInt(flow_start, 10, 64)

	if err != nil {
		return nil, fmt.Errorf("Cannot decode flow start: %w", err)
	}

	flow_end_int, err := strconv.ParseInt(flow_end, 10, 64)

	if err != nil {
		return nil, fmt.Errorf("Cannot decode flow end: %w", err)
	}

	flow_log.Duration = flow_end_int - flow_start_int

	flow_log.Packets = uint64(packets_number)
	flow_log.Protocol_version = 4

	return flow_log, nil
}

func flow_log_into_capnp(flow_log *VPCFlowLog, client *net.UDPConn) error {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		return fmt.Errorf("Cannot create new message: %w", err)
	}

	simple_packet, err := fastnetmon.NewRootSimplePacketType(seg)
	if err != nil {
		return fmt.Errorf("Cannot create capnp type: %w", err)
	}

	simple_packet.SetSrcIp(ip2int(flow_log.Src_ip))
	simple_packet.SetDstIp(ip2int(flow_log.Dst_ip))

	simple_packet.SetSourcePort(flow_log.Src_port)
	simple_packet.SetDestinationPort(flow_log.Dst_port)

	simple_packet.SetIpProtocolVersion(flow_log.Protocol_version)
	simple_packet.SetProtocol(flow_log.Protocol)

	simple_packet.SetLength(flow_log.Bytes)
	simple_packet.SetNumberOfPackets(flow_log.Packets)

	// FNM multiplies length by this value, we need to keep it non zero
	simple_packet.SetSampleRatio(1)

	// Write the message to UDP socket
	err = capnp.NewEncoder(client).Encode(msg)
	if err != nil {
		return fmt.Errorf("Cannot encode message to capnp: %w", err)
	}

	return nil
}

// Description of interface
type InterfaceDetails struct {
	InternalIP net.IP
	ExternalIP net.IP
}

func get_external_ip_for_interface(region string) (map[string]InterfaceDetails, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	if err != nil {
		return nil, fmt.Errorf("Cannot create API session: %w", err)
	}

	// Create new EC2 client
	ec2Svc := ec2.New(sess)

	// We do not use any filters here, we need all of them
	input := &ec2.DescribeNetworkInterfacesInput{}

	result_interfaces, err := ec2Svc.DescribeNetworkInterfaces(input)
	if err != nil {
		return nil, fmt.Errorf("Cannot get interface information: %w", err)
	}

	// We need to have at least single interface in answer
	if len(result_interfaces.NetworkInterfaces) == 0 {
		return nil, fmt.Errorf("Unexpected number of interfaces in answer: %v", len(result_interfaces.NetworkInterfaces))
	}

	interface_map := make(map[string]InterfaceDetails)

	for _, current_interface := range result_interfaces.NetworkInterfaces {
		if current_interface.Association == nil {
			continue
		}

		if current_interface.Association.PublicIp == nil || len(*current_interface.Association.PublicIp) == 0 {
			continue
		}

		if current_interface.PrivateIpAddress == nil || *current_interface.PrivateIpAddress == "" {
			continue
		}

		if current_interface.NetworkInterfaceId == nil || *current_interface.NetworkInterfaceId == "" {
			continue
		}

		internalIP := net.ParseIP(*current_interface.PrivateIpAddress)

		if internalIP == nil {
			continue
		}

		externalIP := net.ParseIP(*current_interface.Association.PublicIp)

		if externalIP == nil {
			continue
		}

		interface_map[*current_interface.NetworkInterfaceId] = InterfaceDetails{InternalIP: internalIP, ExternalIP: externalIP}
	}

	return interface_map, nil
}

// This function wraps all operations for interface_info with mutexes
func get_interface_info(interface_name string) *InterfaceDetails {
	interface_info_mutex.RLock()
	defer interface_info_mutex.RUnlock()

	// We had issues with initlization of logic
	if interface_info == nil {
		return nil
	}

	interface_info, ok := interface_info[interface_name]

	if ok {
		return &interface_info
	}

	return nil
}
