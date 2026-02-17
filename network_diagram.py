#!/usr/bin/env python3
"""
AWS Network Diagram Tool v3.3

A comprehensive tool for visualizing AWS Transit Gateway and VPC network architecture.
Generates interactive HTML reports with full route table details.

Features:
- Full TGW route table visualization (all AWS fields)
- TGW attachments with complete details  
- Cross-account detection for RAM-shared TGWs
- Hub/Spoke multi-account support
- VPN connections with tunnel status monitoring
- Direct Connect with BGP session monitoring
- VPC route tables with destinations and targets
- Subnet classification (public/private/isolated/tgw)
- VPC Peering connections
- Connectivity analysis and issue detection
- Interactive HTML report output
- Mermaid diagram export

Changelog:
- v3.3: Multi-account support (hub/spoke detection, spoke-focused diagrams)
- v3.2: Direct Connect support (connections, VIFs, BGP peers, DX gateways)
- v3.1: Added VPN monitoring, cross-account detection, subnet grouping by RT
- v3.0: Full TGW route tables, HTML tabs, connectivity analysis
- v2.0: Added VPC route tables, subnet classification
- v1.0: Initial TGW visualization

Usage:
    ./export_aws_data.sh ./aws-data us-east-1 my-profile
    python network_diagram.py -i ./aws-data -o report.html
"""

import json
import argparse
import ipaddress
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from collections import defaultdict
from datetime import datetime
import html


# =============================================================================
# ENUMS
# =============================================================================

class AttachmentType(Enum):
    VPC = "vpc"
    VPN = "vpn"
    DIRECT_CONNECT = "direct-connect-gateway"
    PEERING = "peering"
    TGW_PEERING = "tgw-peering"
    CONNECT = "connect"
    UNKNOWN = "unknown"


class RouteType(Enum):
    STATIC = "static"
    PROPAGATED = "propagated"


class RouteState(Enum):
    ACTIVE = "active"
    BLACKHOLE = "blackhole"


class SubnetType(Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    ISOLATED = "isolated"
    TGW_ATTACHED = "tgw"


class RouteTargetType(Enum):
    LOCAL = "local"
    IGW = "igw"
    NAT = "nat"
    TGW = "tgw"
    VPC_PEERING = "pcx"
    VPC_ENDPOINT = "vpce"
    VGW = "vgw"
    ENI = "eni"
    EGRESS_IGW = "eigw"
    UNKNOWN = "unknown"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class TGWRoute:
    """A route in a TGW route table with all AWS fields."""
    destination_cidr: str
    prefix_list_id: Optional[str]
    attachment_id: Optional[str]
    resource_id: Optional[str]
    resource_type: Optional[str]
    route_type: RouteType
    state: RouteState
    
    @property
    def destination(self) -> str:
        return self.prefix_list_id or self.destination_cidr or ""
    
    @property
    def is_blackhole(self) -> bool:
        return self.state == RouteState.BLACKHOLE


@dataclass
class TGWRouteTable:
    """A Transit Gateway route table."""
    id: str
    tgw_id: str
    name: str
    is_default_association: bool
    is_default_propagation: bool
    routes: list[TGWRoute] = field(default_factory=list)
    associations: list[str] = field(default_factory=list)  # attachment IDs
    propagations: list[str] = field(default_factory=list)  # attachment IDs


@dataclass
class TGWAttachment:
    """A TGW attachment with all details."""
    id: str
    tgw_id: str
    type: AttachmentType
    resource_id: str
    resource_owner_id: str
    name: str
    state: str
    cidrs: list[str] = field(default_factory=list)
    associated_route_table_id: Optional[str] = None
    propagating_to: list[str] = field(default_factory=list)
    is_cross_account: bool = False
    tgw_owner_id: str = ""
    
    @property
    def owner_display(self) -> str:
        """Short account display - last 4 digits or 'local'."""
        if not self.is_cross_account:
            return "local"
        return f"...{self.resource_owner_id[-4:]}" if self.resource_owner_id else "?"
    
    @property
    def account_badge(self) -> str:
        """Account badge for display."""
        if self.is_cross_account:
            return f"🔗 {self.resource_owner_id}"
        return "local"


@dataclass
class VPCRoute:
    """A route in a VPC route table."""
    destination: str
    target_type: RouteTargetType
    target_id: str
    state: RouteState
    
    @property
    def is_blackhole(self) -> bool:
        return self.state == RouteState.BLACKHOLE


@dataclass
class VPCRouteTable:
    """A VPC route table."""
    id: str
    vpc_id: str
    name: str
    is_main: bool
    routes: list[VPCRoute] = field(default_factory=list)
    subnet_ids: list[str] = field(default_factory=list)


@dataclass
class Subnet:
    """A VPC subnet."""
    id: str
    vpc_id: str
    cidr: str
    az: str
    name: str
    route_table_id: Optional[str] = None
    subnet_type: SubnetType = SubnetType.ISOLATED


@dataclass
class VPCPeering:
    """A VPC peering connection."""
    id: str
    name: str
    status: str
    requester_vpc_id: str
    requester_cidr: str
    accepter_vpc_id: str
    accepter_cidr: str


@dataclass
class VPNTunnel:
    """A VPN tunnel with telemetry."""
    outside_ip: str
    status: str  # UP, DOWN
    status_message: str
    accepted_route_count: int
    last_status_change: str


@dataclass
class VPNConnection:
    """A Site-to-Site VPN connection."""
    id: str
    name: str
    state: str
    customer_gateway_id: str
    tgw_id: Optional[str]
    vpn_gateway_id: Optional[str]
    tunnels: list[VPNTunnel] = field(default_factory=list)
    static_routes_only: bool = False
    enable_acceleration: bool = False
    local_cidr: str = "0.0.0.0/0"
    remote_cidr: str = "0.0.0.0/0"
    routes: list[str] = field(default_factory=list)  # Propagated CIDRs
    
    @property
    def tunnel_status(self) -> str:
        """Overall tunnel status."""
        up_count = sum(1 for t in self.tunnels if t.status == "UP")
        total = len(self.tunnels)
        if up_count == total:
            return "all_up"
        elif up_count > 0:
            return "partial"
        else:
            return "down"
    
    @property
    def tunnel_summary(self) -> str:
        """Human readable tunnel summary."""
        up_count = sum(1 for t in self.tunnels if t.status == "UP")
        return f"{up_count}/{len(self.tunnels)} tunnels UP"


@dataclass
class CustomerGateway:
    """A customer gateway for VPN."""
    id: str
    name: str
    ip_address: str
    bgp_asn: str
    state: str
    device_name: str = ""


@dataclass
class BGPPeer:
    """A BGP peer on a Direct Connect VIF."""
    peer_id: str
    asn: int
    amazon_address: str
    customer_address: str
    bgp_state: str  # available, pending, etc.
    bgp_status: str  # up, down


@dataclass
class DXConnection:
    """A Direct Connect connection."""
    id: str
    name: str
    state: str  # available, down, ordering, etc.
    location: str
    bandwidth: str
    vlan: int
    partner_name: str
    provider_name: str
    has_logical_redundancy: bool
    aws_device: str


@dataclass
class DXVirtualInterface:
    """A Direct Connect Virtual Interface."""
    id: str
    name: str
    vif_type: str  # transit, private, public
    state: str
    connection_id: str
    vlan: int
    customer_asn: int
    amazon_asn: int
    amazon_address: str
    customer_address: str
    mtu: int
    jumbo_capable: bool
    bgp_peers: list[BGPPeer] = field(default_factory=list)
    dx_gateway_id: Optional[str] = None
    virtual_gateway_id: Optional[str] = None
    route_filter_prefixes: list[str] = field(default_factory=list)
    
    @property
    def bgp_status(self) -> str:
        """Overall BGP status."""
        if not self.bgp_peers:
            return "no_peers"
        up_count = sum(1 for p in self.bgp_peers if p.bgp_status.lower() == "up")
        if up_count == len(self.bgp_peers):
            return "all_up"
        elif up_count > 0:
            return "partial"
        return "down"
    
    @property
    def bgp_summary(self) -> str:
        """Human readable BGP summary."""
        up_count = sum(1 for p in self.bgp_peers if p.bgp_status.lower() == "up")
        return f"{up_count}/{len(self.bgp_peers)} BGP UP"


@dataclass
class DXGateway:
    """A Direct Connect Gateway."""
    id: str
    name: str
    amazon_asn: int
    owner_account: str
    state: str


@dataclass
class VPC:
    """A VPC with all its components."""
    id: str
    name: str
    cidrs: list[str]
    owner_id: str
    is_default: bool = False
    igw_id: Optional[str] = None
    nat_gateway_ids: list[str] = field(default_factory=list)
    tgw_attachment_id: Optional[str] = None
    main_route_table_id: Optional[str] = None


@dataclass
class TransitGateway:
    """A Transit Gateway."""
    id: str
    name: str
    owner_id: str
    asn: int
    state: str


@dataclass 
class NetworkData:
    """Container for all network data."""
    tgws: dict[str, TransitGateway] = field(default_factory=dict)
    tgw_route_tables: dict[str, TGWRouteTable] = field(default_factory=dict)
    tgw_attachments: dict[str, TGWAttachment] = field(default_factory=dict)
    vpcs: dict[str, VPC] = field(default_factory=dict)
    vpc_route_tables: dict[str, VPCRouteTable] = field(default_factory=dict)
    subnets: dict[str, Subnet] = field(default_factory=dict)
    peerings: dict[str, VPCPeering] = field(default_factory=dict)
    vpn_connections: dict[str, VPNConnection] = field(default_factory=dict)
    customer_gateways: dict[str, CustomerGateway] = field(default_factory=dict)
    dx_connections: dict[str, DXConnection] = field(default_factory=dict)
    dx_vifs: dict[str, DXVirtualInterface] = field(default_factory=dict)
    dx_gateways: dict[str, DXGateway] = field(default_factory=dict)
    igws: dict[str, str] = field(default_factory=dict)  # igw_id -> vpc_id
    nat_gateways: dict[str, dict] = field(default_factory=dict)
    prefix_lists: dict[str, str] = field(default_factory=dict)  # pl_id -> name
    local_account_id: str = ""
    
    @property
    def is_hub_account(self) -> bool:
        """True if this account owns a TGW (hub/network account)."""
        return len(self.tgws) > 0
    
    @property
    def is_spoke_account(self) -> bool:
        """True if this account has TGW attachments but no TGW (spoke account)."""
        return len(self.tgws) == 0 and len(self.tgw_attachments) > 0
    
    @property
    def referenced_tgw_ids(self) -> set[str]:
        """Get TGW IDs referenced by attachments (useful for spoke accounts)."""
        return {att.tgw_id for att in self.tgw_attachments.values() if att.tgw_id}
    
    @property
    def cross_account_attachments(self) -> list[TGWAttachment]:
        return [a for a in self.tgw_attachments.values() if a.is_cross_account]
    
    @property
    def local_attachments(self) -> list[TGWAttachment]:
        return [a for a in self.tgw_attachments.values() if not a.is_cross_account]


# =============================================================================
# DATA LOADER
# =============================================================================

class AWSDataLoader:
    """Loads AWS CLI JSON output files."""
    
    def __init__(self, input_dir: Path):
        self.input_dir = input_dir
        self.data = NetworkData()
    
    def load(self) -> NetworkData:
        """Load all data from JSON files."""
        self._load_metadata()
        self._load_tgws()
        self._load_tgw_attachments()
        self._load_tgw_route_tables()
        self._load_tgw_route_details()
        self._load_vpcs()
        self._load_subnets()
        self._load_vpc_route_tables()
        self._load_igws()
        self._load_nat_gateways()
        self._load_peerings()
        self._load_vpn_connections()
        self._load_customer_gateways()
        self._load_dx_connections()
        self._load_dx_gateways()
        self._load_dx_vifs()
        self._load_prefix_lists()
        self._correlate_data()
        self._extract_cross_account_cidrs()
        self._classify_subnets()
        return self.data
    
    def _read_json(self, filename: str) -> dict:
        path = self.input_dir / filename
        if not path.exists():
            return {}
        with open(path) as f:
            return json.load(f)
    
    def _get_name(self, tags: list) -> str:
        for tag in (tags or []):
            if tag.get("Key") == "Name":
                return tag.get("Value", "")
        return ""
    
    def _load_metadata(self):
        """Load metadata to get local account ID."""
        data = self._read_json("metadata.json")
        self.data.local_account_id = data.get("aws_account_id", "")
    
    def _load_tgws(self):
        data = self._read_json("transit-gateways.json")
        for tgw in data.get("TransitGateways", []):
            self.data.tgws[tgw["TransitGatewayId"]] = TransitGateway(
                id=tgw["TransitGatewayId"],
                name=self._get_name(tgw.get("Tags")) or tgw["TransitGatewayId"],
                owner_id=tgw.get("OwnerId", ""),
                asn=tgw.get("Options", {}).get("AmazonSideAsn", 0),
                state=tgw.get("State", "")
            )
    
    def _load_tgw_attachments(self):
        data = self._read_json("transit-gateway-attachments.json")
        for att in data.get("TransitGatewayAttachments", []):
            att_type_str = att.get("ResourceType", "unknown")
            try:
                att_type = AttachmentType(att_type_str)
            except ValueError:
                att_type = AttachmentType.UNKNOWN
            
            resource_owner = att.get("ResourceOwnerId", "")
            tgw_owner = att.get("TransitGatewayOwnerId", "")
            
            # Determine if cross-account
            # Cross-account if resource owner != TGW owner (or != local account if TGW owner not available)
            is_cross_account = False
            if tgw_owner and resource_owner:
                is_cross_account = (resource_owner != tgw_owner)
            elif self.data.local_account_id and resource_owner:
                is_cross_account = (resource_owner != self.data.local_account_id)
            
            self.data.tgw_attachments[att["TransitGatewayAttachmentId"]] = TGWAttachment(
                id=att["TransitGatewayAttachmentId"],
                tgw_id=att["TransitGatewayId"],
                type=att_type,
                resource_id=att.get("ResourceId", ""),
                resource_owner_id=resource_owner,
                name=self._get_name(att.get("Tags")) or att.get("ResourceId", ""),
                state=att.get("State", ""),
                is_cross_account=is_cross_account,
                tgw_owner_id=tgw_owner
            )
    
    def _load_tgw_route_tables(self):
        data = self._read_json("transit-gateway-route-tables.json")
        for rt in data.get("TransitGatewayRouteTables", []):
            self.data.tgw_route_tables[rt["TransitGatewayRouteTableId"]] = TGWRouteTable(
                id=rt["TransitGatewayRouteTableId"],
                tgw_id=rt["TransitGatewayId"],
                name=self._get_name(rt.get("Tags")) or rt["TransitGatewayRouteTableId"],
                is_default_association=rt.get("DefaultAssociationRouteTable", False),
                is_default_propagation=rt.get("DefaultPropagationRouteTable", False)
            )
    
    def _load_tgw_route_details(self):
        # Load associations
        for f in self.input_dir.glob("associations-*.json"):
            rt_id = f.stem.replace("associations-", "")
            if rt_id not in self.data.tgw_route_tables:
                continue
            
            data = self._read_json(f.name)
            rt = self.data.tgw_route_tables[rt_id]
            
            for assoc in data.get("Associations", []):
                if assoc.get("State") == "associated":
                    att_id = assoc.get("TransitGatewayAttachmentId")
                    if att_id:
                        rt.associations.append(att_id)
                        if att_id in self.data.tgw_attachments:
                            self.data.tgw_attachments[att_id].associated_route_table_id = rt_id
        
        # Load propagations
        for f in self.input_dir.glob("propagations-*.json"):
            rt_id = f.stem.replace("propagations-", "")
            if rt_id not in self.data.tgw_route_tables:
                continue
            
            data = self._read_json(f.name)
            rt = self.data.tgw_route_tables[rt_id]
            
            for prop in data.get("TransitGatewayRouteTablePropagations", []):
                if prop.get("State") == "enabled":
                    att_id = prop.get("TransitGatewayAttachmentId")
                    if att_id:
                        rt.propagations.append(att_id)
                        if att_id in self.data.tgw_attachments:
                            self.data.tgw_attachments[att_id].propagating_to.append(rt_id)
        
        # Load routes
        for f in self.input_dir.glob("routes-*.json"):
            rt_id = f.stem.replace("routes-", "")
            if rt_id not in self.data.tgw_route_tables:
                continue
            
            data = self._read_json(f.name)
            rt = self.data.tgw_route_tables[rt_id]
            
            for route in data.get("Routes", []):
                state = RouteState.BLACKHOLE if route.get("State") == "blackhole" else RouteState.ACTIVE
                route_type = RouteType.PROPAGATED if route.get("Type") == "propagated" else RouteType.STATIC
                
                att_id = None
                resource_id = None
                resource_type = None
                
                for att in route.get("TransitGatewayAttachments", []):
                    att_id = att.get("TransitGatewayAttachmentId")
                    resource_id = att.get("ResourceId")
                    resource_type = att.get("ResourceType")
                    break
                
                rt.routes.append(TGWRoute(
                    destination_cidr=route.get("DestinationCidrBlock", ""),
                    prefix_list_id=route.get("PrefixListId"),
                    attachment_id=att_id,
                    resource_id=resource_id,
                    resource_type=resource_type,
                    route_type=route_type,
                    state=state
                ))
    
    def _load_vpcs(self):
        data = self._read_json("vpcs.json")
        for vpc in data.get("Vpcs", []):
            cidrs = [vpc.get("CidrBlock", "")]
            for assoc in vpc.get("CidrBlockAssociationSet", []):
                if assoc.get("CidrBlock") not in cidrs:
                    cidrs.append(assoc["CidrBlock"])
            
            self.data.vpcs[vpc["VpcId"]] = VPC(
                id=vpc["VpcId"],
                name=self._get_name(vpc.get("Tags")) or vpc["VpcId"],
                cidrs=cidrs,
                owner_id=vpc.get("OwnerId", ""),
                is_default=vpc.get("IsDefault", False)
            )
    
    def _load_subnets(self):
        data = self._read_json("subnets.json")
        for subnet in data.get("Subnets", []):
            self.data.subnets[subnet["SubnetId"]] = Subnet(
                id=subnet["SubnetId"],
                vpc_id=subnet["VpcId"],
                cidr=subnet.get("CidrBlock", ""),
                az=subnet.get("AvailabilityZone", ""),
                name=self._get_name(subnet.get("Tags")) or subnet["SubnetId"]
            )
    
    def _load_vpc_route_tables(self):
        data = self._read_json("vpc-route-tables.json")
        for rt in data.get("RouteTables", []):
            vpc_rt = VPCRouteTable(
                id=rt["RouteTableId"],
                vpc_id=rt["VpcId"],
                name=self._get_name(rt.get("Tags")) or rt["RouteTableId"],
                is_main=False
            )
            
            for assoc in rt.get("Associations", []):
                if assoc.get("Main"):
                    vpc_rt.is_main = True
                    if rt["VpcId"] in self.data.vpcs:
                        self.data.vpcs[rt["VpcId"]].main_route_table_id = rt["RouteTableId"]
                
                subnet_id = assoc.get("SubnetId")
                if subnet_id:
                    vpc_rt.subnet_ids.append(subnet_id)
                    if subnet_id in self.data.subnets:
                        self.data.subnets[subnet_id].route_table_id = rt["RouteTableId"]
            
            for route in rt.get("Routes", []):
                dest = route.get("DestinationCidrBlock") or route.get("DestinationPrefixListId") or ""
                target_type, target_id = self._parse_vpc_route_target(route)
                state = RouteState.BLACKHOLE if route.get("State") == "blackhole" else RouteState.ACTIVE
                
                vpc_rt.routes.append(VPCRoute(
                    destination=dest,
                    target_type=target_type,
                    target_id=target_id,
                    state=state
                ))
            
            self.data.vpc_route_tables[rt["RouteTableId"]] = vpc_rt
    
    def _parse_vpc_route_target(self, route: dict) -> tuple[RouteTargetType, str]:
        if route.get("GatewayId"):
            gw = route["GatewayId"]
            if gw == "local":
                return RouteTargetType.LOCAL, "local"
            elif gw.startswith("igw-"):
                return RouteTargetType.IGW, gw
            elif gw.startswith("vgw-"):
                return RouteTargetType.VGW, gw
            elif gw.startswith("eigw-"):
                return RouteTargetType.EGRESS_IGW, gw
            elif gw.startswith("vpce-"):
                return RouteTargetType.VPC_ENDPOINT, gw
        
        if route.get("NatGatewayId"):
            return RouteTargetType.NAT, route["NatGatewayId"]
        if route.get("TransitGatewayId"):
            return RouteTargetType.TGW, route["TransitGatewayId"]
        if route.get("VpcPeeringConnectionId"):
            return RouteTargetType.VPC_PEERING, route["VpcPeeringConnectionId"]
        if route.get("NetworkInterfaceId"):
            return RouteTargetType.ENI, route["NetworkInterfaceId"]
        
        return RouteTargetType.UNKNOWN, ""
    
    def _load_igws(self):
        data = self._read_json("internet-gateways.json")
        for igw in data.get("InternetGateways", []):
            for att in igw.get("Attachments", []):
                if att.get("State") == "available":
                    vpc_id = att.get("VpcId")
                    self.data.igws[igw["InternetGatewayId"]] = vpc_id
                    if vpc_id in self.data.vpcs:
                        self.data.vpcs[vpc_id].igw_id = igw["InternetGatewayId"]
    
    def _load_nat_gateways(self):
        data = self._read_json("nat-gateways.json")
        for nat in data.get("NatGateways", []):
            self.data.nat_gateways[nat["NatGatewayId"]] = {
                "id": nat["NatGatewayId"],
                "vpc_id": nat.get("VpcId"),
                "subnet_id": nat.get("SubnetId"),
                "state": nat.get("State"),
                "name": self._get_name(nat.get("Tags")) or nat["NatGatewayId"]
            }
            if nat.get("VpcId") in self.data.vpcs:
                self.data.vpcs[nat["VpcId"]].nat_gateway_ids.append(nat["NatGatewayId"])
    
    def _load_peerings(self):
        data = self._read_json("vpc-peering-connections.json")
        for pcx in data.get("VpcPeeringConnections", []):
            req = pcx.get("RequesterVpcInfo", {})
            acc = pcx.get("AccepterVpcInfo", {})
            self.data.peerings[pcx["VpcPeeringConnectionId"]] = VPCPeering(
                id=pcx["VpcPeeringConnectionId"],
                name=self._get_name(pcx.get("Tags")) or pcx["VpcPeeringConnectionId"],
                status=pcx.get("Status", {}).get("Code", ""),
                requester_vpc_id=req.get("VpcId", ""),
                requester_cidr=req.get("CidrBlock", ""),
                accepter_vpc_id=acc.get("VpcId", ""),
                accepter_cidr=acc.get("CidrBlock", "")
            )
    
    def _load_vpn_connections(self):
        data = self._read_json("vpn-connections.json")
        for vpn in data.get("VpnConnections", []):
            vpn_id = vpn.get("VpnConnectionId", "")
            
            # Parse tunnels from VgwTelemetry
            tunnels = []
            for telem in vpn.get("VgwTelemetry", []):
                tunnels.append(VPNTunnel(
                    outside_ip=telem.get("OutsideIpAddress", ""),
                    status=telem.get("Status", "DOWN"),
                    status_message=telem.get("StatusMessage", ""),
                    accepted_route_count=telem.get("AcceptedRouteCount", 0),
                    last_status_change=telem.get("LastStatusChange", "")
                ))
            
            # Parse options
            options = vpn.get("Options", {})
            
            # Parse routes
            routes = [r.get("DestinationCidrBlock", "") for r in vpn.get("Routes", [])]
            
            self.data.vpn_connections[vpn_id] = VPNConnection(
                id=vpn_id,
                name=self._get_name(vpn.get("Tags")) or vpn_id,
                state=vpn.get("State", ""),
                customer_gateway_id=vpn.get("CustomerGatewayId", ""),
                tgw_id=vpn.get("TransitGatewayId"),
                vpn_gateway_id=vpn.get("VpnGatewayId"),
                tunnels=tunnels,
                static_routes_only=options.get("StaticRoutesOnly", False),
                enable_acceleration=options.get("EnableAcceleration", False),
                local_cidr=options.get("LocalIpv4NetworkCidr", "0.0.0.0/0"),
                remote_cidr=options.get("RemoteIpv4NetworkCidr", "0.0.0.0/0"),
                routes=routes
            )
    
    def _load_customer_gateways(self):
        data = self._read_json("customer-gateways.json")
        for cgw in data.get("CustomerGateways", []):
            cgw_id = cgw.get("CustomerGatewayId", "")
            self.data.customer_gateways[cgw_id] = CustomerGateway(
                id=cgw_id,
                name=self._get_name(cgw.get("Tags")) or cgw_id,
                ip_address=cgw.get("IpAddress", ""),
                bgp_asn=cgw.get("BgpAsn", ""),
                state=cgw.get("State", ""),
                device_name=cgw.get("DeviceName", "")
            )
    
    def _load_dx_connections(self):
        data = self._read_json("dx-connections.json")
        for conn in data.get("connections", []):
            conn_id = conn.get("connectionId", "")
            self.data.dx_connections[conn_id] = DXConnection(
                id=conn_id,
                name=conn.get("connectionName", "") or self._get_name(conn.get("tags")) or conn_id,
                state=conn.get("connectionState", ""),
                location=conn.get("location", ""),
                bandwidth=conn.get("bandwidth", ""),
                vlan=conn.get("vlan", 0),
                partner_name=conn.get("partnerName", ""),
                provider_name=conn.get("providerName", ""),
                has_logical_redundancy=conn.get("hasLogicalRedundancy", "no") == "yes",
                aws_device=conn.get("awsDeviceV2", "") or conn.get("awsDevice", "")
            )
    
    def _load_dx_gateways(self):
        data = self._read_json("dx-gateways.json")
        for gw in data.get("directConnectGateways", []):
            gw_id = gw.get("directConnectGatewayId", "")
            self.data.dx_gateways[gw_id] = DXGateway(
                id=gw_id,
                name=gw.get("directConnectGatewayName", "") or gw_id,
                amazon_asn=gw.get("amazonSideAsn", 0),
                owner_account=gw.get("ownerAccount", ""),
                state=gw.get("directConnectGatewayState", "")
            )
    
    def _load_dx_vifs(self):
        data = self._read_json("dx-vifs.json")
        for vif in data.get("virtualInterfaces", []):
            vif_id = vif.get("virtualInterfaceId", "")
            
            # Parse BGP peers
            bgp_peers = []
            for peer in vif.get("bgpPeers", []):
                bgp_peers.append(BGPPeer(
                    peer_id=peer.get("bgpPeerId", ""),
                    asn=peer.get("asn", 0),
                    amazon_address=peer.get("amazonAddress", ""),
                    customer_address=peer.get("customerAddress", ""),
                    bgp_state=peer.get("bgpPeerState", ""),
                    bgp_status=peer.get("bgpStatus", "down")
                ))
            
            # Parse route filter prefixes
            prefixes = [p.get("cidr", "") for p in vif.get("routeFilterPrefixes", [])]
            
            self.data.dx_vifs[vif_id] = DXVirtualInterface(
                id=vif_id,
                name=vif.get("virtualInterfaceName", "") or self._get_name(vif.get("tags")) or vif_id,
                vif_type=vif.get("virtualInterfaceType", ""),
                state=vif.get("virtualInterfaceState", ""),
                connection_id=vif.get("connectionId", ""),
                vlan=vif.get("vlan", 0),
                customer_asn=vif.get("asn", 0),
                amazon_asn=vif.get("amazonSideAsn", 0),
                amazon_address=vif.get("amazonAddress", ""),
                customer_address=vif.get("customerAddress", ""),
                mtu=vif.get("mtu", 1500),
                jumbo_capable=vif.get("jumboFrameCapable", False),
                bgp_peers=bgp_peers,
                dx_gateway_id=vif.get("directConnectGatewayId"),
                virtual_gateway_id=vif.get("virtualGatewayId"),
                route_filter_prefixes=prefixes
            )
    
    def _load_prefix_lists(self):
        data = self._read_json("prefix-lists.json")
        for pl in data.get("PrefixLists", []):
            name = pl.get("PrefixListName", "")
            # Extract service name from AWS prefix list name
            if name.startswith("com.amazonaws."):
                parts = name.split(".")
                if len(parts) >= 4:
                    name = parts[-1]
            self.data.prefix_lists[pl["PrefixListId"]] = name
    
    def _correlate_data(self):
        # Link VPCs to TGW attachments
        for att in self.data.tgw_attachments.values():
            if att.type == AttachmentType.VPC:
                vpc_id = att.resource_id
                if vpc_id in self.data.vpcs:
                    vpc = self.data.vpcs[vpc_id]
                    att.cidrs = vpc.cidrs
                    att.name = vpc.name
                    vpc.tgw_attachment_id = att.id
    
    def _extract_cross_account_cidrs(self):
        """
        Extract CIDRs from propagated routes for cross-account VPCs.
        When running from Network account, we can't describe spoke VPCs,
        but we CAN see their CIDRs in the propagated routes.
        """
        # Build a map of attachment_id -> CIDRs from propagated routes
        att_cidrs = defaultdict(set)
        
        for rt in self.data.tgw_route_tables.values():
            for route in rt.routes:
                if route.route_type == RouteType.PROPAGATED and route.attachment_id:
                    if route.destination_cidr:
                        att_cidrs[route.attachment_id].add(route.destination_cidr)
        
        # Update attachments that don't have CIDRs yet (cross-account VPCs)
        for att in self.data.tgw_attachments.values():
            if att.type == AttachmentType.VPC and not att.cidrs:
                if att.id in att_cidrs:
                    att.cidrs = sorted(list(att_cidrs[att.id]))
            
            # For VPNs, also extract CIDRs from propagated routes
            if att.type == AttachmentType.VPN and not att.cidrs:
                if att.id in att_cidrs:
                    att.cidrs = sorted(list(att_cidrs[att.id]))
    
    def _classify_subnets(self):
        for subnet in self.data.subnets.values():
            rt_id = subnet.route_table_id
            if not rt_id:
                vpc = self.data.vpcs.get(subnet.vpc_id)
                if vpc:
                    rt_id = vpc.main_route_table_id
            
            if not rt_id or rt_id not in self.data.vpc_route_tables:
                subnet.subnet_type = SubnetType.ISOLATED
                continue
            
            rt = self.data.vpc_route_tables[rt_id]
            
            for route in rt.routes:
                if route.destination in ("0.0.0.0/0", "::/0"):
                    if route.target_type == RouteTargetType.IGW:
                        subnet.subnet_type = SubnetType.PUBLIC
                        break
                    elif route.target_type == RouteTargetType.NAT:
                        subnet.subnet_type = SubnetType.PRIVATE
                        break
                    elif route.target_type == RouteTargetType.TGW:
                        subnet.subnet_type = SubnetType.TGW_ATTACHED
                        break


# =============================================================================
# CONNECTIVITY ANALYZER
# =============================================================================

class ConnectivityAnalyzer:
    """Analyzes network connectivity and detects issues."""
    
    def __init__(self, data: NetworkData):
        self.data = data
    
    def find_issues(self) -> list[dict]:
        issues = []
        issues.extend(self._check_blackholes())
        issues.extend(self._check_asymmetric_routing())
        issues.extend(self._check_peering_issues())
        issues.extend(self._check_cidr_overlaps())
        issues.extend(self._check_missing_routes())
        issues.extend(self._check_vpn_tunnels())
        issues.extend(self._check_dx_issues())
        return issues
    
    def _check_dx_issues(self) -> list[dict]:
        """Check for Direct Connect issues."""
        issues = []
        
        # Check DX connections
        for conn in self.data.dx_connections.values():
            if conn.state == "down":
                issues.append({
                    "type": "dx_down",
                    "severity": "error",
                    "location": conn.name,
                    "message": f"Direct Connect connection {conn.name} is DOWN at {conn.location}"
                })
            elif conn.state not in ["available", "ordering", "requested"]:
                issues.append({
                    "type": "dx_degraded",
                    "severity": "warning",
                    "location": conn.name,
                    "message": f"Direct Connect connection {conn.name} is in state: {conn.state}"
                })
        
        # Check VIF BGP sessions
        for vif in self.data.dx_vifs.values():
            if vif.state != "available":
                issues.append({
                    "type": "vif_down",
                    "severity": "error",
                    "location": vif.name,
                    "message": f"VIF {vif.name} is in state: {vif.state}"
                })
            
            # Check BGP peers
            bgp_down = [p for p in vif.bgp_peers if p.bgp_status.lower() != "up"]
            bgp_up = [p for p in vif.bgp_peers if p.bgp_status.lower() == "up"]
            
            if len(bgp_down) == len(vif.bgp_peers) and len(vif.bgp_peers) > 0:
                issues.append({
                    "type": "bgp_down",
                    "severity": "error",
                    "location": vif.name,
                    "message": f"All BGP peers DOWN for VIF {vif.name}"
                })
            elif bgp_down:
                for peer in bgp_down:
                    issues.append({
                        "type": "bgp_partial",
                        "severity": "warning",
                        "location": vif.name,
                        "message": f"BGP peer ASN {peer.asn} ({peer.customer_address}) DOWN on {vif.name}"
                    })
        
        return issues
    
    def _check_vpn_tunnels(self) -> list[dict]:
        """Check for VPN tunnel issues."""
        issues = []
        for vpn in self.data.vpn_connections.values():
            tunnels_down = [t for t in vpn.tunnels if t.status != "UP"]
            tunnels_up = [t for t in vpn.tunnels if t.status == "UP"]
            
            if len(tunnels_down) == len(vpn.tunnels) and len(vpn.tunnels) > 0:
                # All tunnels down
                issues.append({
                    "type": "vpn_down",
                    "severity": "error",
                    "location": vpn.name,
                    "message": f"All tunnels DOWN for VPN {vpn.name}"
                })
            elif tunnels_down:
                # Some tunnels down
                for tunnel in tunnels_down:
                    msg = tunnel.status_message if tunnel.status_message else "No message"
                    issues.append({
                        "type": "vpn_partial",
                        "severity": "warning", 
                        "location": vpn.name,
                        "message": f"Tunnel {tunnel.outside_ip} DOWN for {vpn.name}: {msg}"
                    })
        return issues
    
    def _check_blackholes(self) -> list[dict]:
        issues = []
        for rt in self.data.tgw_route_tables.values():
            for route in rt.routes:
                if route.is_blackhole:
                    issues.append({
                        "type": "blackhole",
                        "severity": "warning",
                        "location": rt.name,
                        "message": f"Blackhole route to {route.destination} in {rt.name}"
                    })
        return issues
    
    def _check_asymmetric_routing(self) -> list[dict]:
        issues = []
        # Check if attachments can reach each other bidirectionally
        for tgw in self.data.tgws.values():
            tgw_atts = [a for a in self.data.tgw_attachments.values() if a.tgw_id == tgw.id]
            
            for src in tgw_atts:
                for dst in tgw_atts:
                    if src.id == dst.id:
                        continue
                    
                    can_reach = self._can_reach(src, dst)
                    can_return = self._can_reach(dst, src)
                    
                    if can_reach and not can_return:
                        issues.append({
                            "type": "asymmetric",
                            "severity": "warning",
                            "location": f"{src.name} → {dst.name}",
                            "message": f"Asymmetric routing: {src.name} can reach {dst.name} but not vice versa"
                        })
        return issues
    
    def _can_reach(self, src: TGWAttachment, dst: TGWAttachment) -> bool:
        if not src.associated_route_table_id:
            return False
        
        rt = self.data.tgw_route_tables.get(src.associated_route_table_id)
        if not rt:
            return False
        
        for cidr in dst.cidrs:
            for route in rt.routes:
                if route.is_blackhole:
                    continue
                if route.attachment_id == dst.id:
                    if self._cidr_matches(route.destination_cidr, cidr):
                        return True
        return False
    
    def _cidr_matches(self, route_cidr: str, target_cidr: str) -> bool:
        if route_cidr == "0.0.0.0/0":
            return True
        try:
            route_net = ipaddress.ip_network(route_cidr, strict=False)
            target_net = ipaddress.ip_network(target_cidr, strict=False)
            return target_net.subnet_of(route_net) or route_net == target_net
        except:
            return route_cidr == target_cidr
    
    def _check_peering_issues(self) -> list[dict]:
        issues = []
        for pcx in self.data.peerings.values():
            if pcx.status != "active":
                issues.append({
                    "type": "peering",
                    "severity": "warning",
                    "location": pcx.name,
                    "message": f"VPC Peering {pcx.name} is not active (status: {pcx.status})"
                })
        return issues
    
    def _check_cidr_overlaps(self) -> list[dict]:
        issues = []
        vpcs = list(self.data.vpcs.values())
        
        for i, vpc1 in enumerate(vpcs):
            for vpc2 in vpcs[i+1:]:
                for cidr1 in vpc1.cidrs:
                    for cidr2 in vpc2.cidrs:
                        try:
                            net1 = ipaddress.ip_network(cidr1, strict=False)
                            net2 = ipaddress.ip_network(cidr2, strict=False)
                            if net1.overlaps(net2):
                                issues.append({
                                    "type": "overlap",
                                    "severity": "warning",
                                    "location": f"{vpc1.name} / {vpc2.name}",
                                    "message": f"CIDR overlap: {vpc1.name} ({cidr1}) overlaps with {vpc2.name} ({cidr2})"
                                })
                        except:
                            pass
        return issues
    
    def _check_missing_routes(self) -> list[dict]:
        issues = []
        # Check for VPCs attached to TGW but without TGW routes
        for vpc in self.data.vpcs.values():
            if vpc.tgw_attachment_id:
                has_tgw_route = False
                for rt in self.data.vpc_route_tables.values():
                    if rt.vpc_id == vpc.id:
                        for route in rt.routes:
                            if route.target_type == RouteTargetType.TGW:
                                has_tgw_route = True
                                break
                
                if not has_tgw_route:
                    issues.append({
                        "type": "missing_route",
                        "severity": "info",
                        "location": vpc.name,
                        "message": f"VPC {vpc.name} is attached to TGW but has no TGW routes in any route table"
                    })
        return issues


# =============================================================================
# HTML REPORT GENERATOR
# =============================================================================

class HTMLReportGenerator:
    """Generates interactive HTML reports."""
    
    def __init__(self, data: NetworkData):
        self.data = data
        self.analyzer = ConnectivityAnalyzer(data)
    
    def generate(self) -> str:
        issues = self.analyzer.find_issues()
        mermaid_code = self._generate_mermaid()
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Network Diagram</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
{self._get_css()}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div>
                <h1>🌐 AWS Network Diagram {self._get_account_mode_badge()}</h1>
                <div class="meta">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Account: {self.data.local_account_id or "Unknown"}{self._get_tgw_reference()}</div>
            </div>
            <div class="header-legend">
                <span class="legend-item vpc">VPC (Local)</span>
                <span class="legend-item cross">VPC (Cross-Account)</span>
                <span class="legend-item vpn">VPN</span>
                <span class="legend-item dx">Direct Connect</span>
            </div>
        </div>
    </div>
    
    {self._get_spoke_guidance_banner()}
    
    <div class="stats-bar">
        {self._generate_stats_bar()}
    </div>
    
    {self._generate_issues_banner(issues) if issues else ""}
    
    <div class="diagram-container">
        <div class="mermaid">
{mermaid_code}
        </div>
    </div>
    
    <div class="details-section">
        <div class="tabs">
            <button class="tab active" onclick="showTab('tgw-tab')">TGW Route Tables</button>
            <button class="tab" onclick="showTab('att-tab')">TGW Attachments</button>
            {self._vpn_tab_button()}
            {self._dx_tab_button()}
            <button class="tab" onclick="showTab('vpc-details-tab')">VPCs &amp; Subnets</button>
            <button class="tab" onclick="showTab('issues-tab')">Issues ({len(issues)})</button>
        </div>
        
        <div id="tgw-tab" class="tab-content active">
            {self._generate_tgw_tables_html()}
        </div>
        
        <div id="att-tab" class="tab-content">
            {self._generate_attachments_html()}
        </div>
        
        {self._vpn_tab_content()}
        
        {self._dx_tab_content()}
        
        <div id="vpc-details-tab" class="tab-content">
            {self._generate_vpc_details_html()}
        </div>
        
        <div id="issues-tab" class="tab-content">
            {self._generate_issues_html(issues)}
        </div>
    </div>
    
    <script>
        mermaid.initialize({{ 
            startOnLoad: true,
            theme: 'default',
            flowchart: {{ useMaxWidth: true, htmlLabels: true, curve: 'basis' }}
        }});
        
        function showTab(tabId) {{
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }}
    </script>
    <footer class="report-footer">
        <div>AWS Network Diagram Tool v3.3</div>
        <div>Generated from AWS CLI exports • <a href="https://github.com" target="_blank">Documentation</a></div>
    </footer>
</body>
</html>'''
    
    def _get_css(self) -> str:
        return '''
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        .header {
            background: linear-gradient(135deg, #232f3e 0%, #37475a 100%);
            color: white;
            padding: 1.5rem 2rem;
        }
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        .header h1 { font-size: 1.5rem; font-weight: 600; margin: 0; }
        .meta { color: #aaa; font-size: 0.85rem; margin-top: 0.25rem; }
        .header-legend {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
        }
        .legend-item {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .legend-item.vpc { background: #3b82f6; }
        .legend-item.cross { background: #e67e22; }
        .legend-item.vpn { background: #22c55e; }
        .legend-item.dx { background: #a855f7; }
        .mode-badge {
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            margin-left: 0.5rem;
            font-weight: 600;
            vertical-align: middle;
        }
        .mode-badge.hub { background: #dcfce7; color: #166534; }
        .mode-badge.spoke { background: #dbeafe; color: #1e40af; }
        .meta code { 
            background: rgba(255,255,255,0.2); 
            padding: 0.1rem 0.3rem; 
            border-radius: 3px; 
            font-size: 0.8rem;
        }
        .spoke-guidance-banner {
            background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
            color: #1e40af;
            padding: 0.75rem 2rem;
            font-size: 0.85rem;
            border-bottom: 1px solid #93c5fd;
        }
        .spoke-guidance-banner strong { margin-right: 0.5rem; }
        .stats-bar {
            display: flex;
            gap: 2rem;
            padding: 1rem 2rem;
            background: white;
            border-bottom: 1px solid #e0e0e0;
            flex-wrap: wrap;
        }
        .stat { text-align: center; }
        .stat-value { font-size: 1.5rem; font-weight: 700; color: #232f3e; }
        .stat-label { font-size: 0.75rem; color: #666; }
        .subnet-mini { display: flex; gap: 0.25rem; margin-top: 0.25rem; justify-content: center; flex-wrap: wrap; }
        .subnet-mini-item { font-size: 0.65rem; padding: 0.1rem 0.3rem; border-radius: 3px; }
        .subnet-mini-item.public { background: #dcfce7; color: #166534; }
        .subnet-mini-item.private { background: #dbeafe; color: #1e40af; }
        .subnet-mini-item.tgw { background: #fef3c7; color: #92400e; }
        .subnet-mini-item.isolated { background: #f3f4f6; color: #4b5563; }
        .issues-banner {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 0.75rem 2rem;
            color: #856404;
        }
        .diagram-container {
            background: white;
            margin: 1rem;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        .mermaid { min-height: 400px; }
        .details-section {
            margin: 1rem;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .tabs {
            display: flex;
            border-bottom: 1px solid #e0e0e0;
            padding: 0 1rem;
        }
        .tab {
            padding: 1rem 1.5rem;
            border: none;
            background: none;
            cursor: pointer;
            font-size: 0.9rem;
            color: #666;
            border-bottom: 2px solid transparent;
        }
        .tab:hover { color: #333; }
        .tab.active { color: #232f3e; border-bottom-color: #ff9900; }
        .tab-content { display: none; padding: 1.5rem; }
        .tab-content.active { display: block; }
        .route-table-card {
            background: #fafafa;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        .route-table-header {
            background: #232f3e;
            color: white;
            padding: 0.75rem 1rem;
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .badge {
            font-size: 0.7rem;
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            background: #ff9900;
            color: #232f3e;
        }
        .route-table-meta {
            padding: 0.75rem 1rem;
            background: #f0f0f0;
            font-size: 0.85rem;
            color: #666;
            border-bottom: 1px solid #e0e0e0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        th {
            background: #f5f5f5;
            text-align: left;
            padding: 0.6rem 1rem;
            font-weight: 600;
            color: #444;
            border-bottom: 1px solid #e0e0e0;
        }
        td {
            padding: 0.5rem 1rem;
            border-bottom: 1px solid #eee;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.8rem;
        }
        tr:hover { background: #f9f9f9; }
        .state-active { color: #28a745; }
        .state-blackhole { color: #dc3545; }
        .route-type { color: #6c757d; font-size: 0.75rem; }
        .attachment-card {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
        }
        .att-card {
            background: #fafafa;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 1rem;
        }
        .att-card-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.75rem;
        }
        .att-icon {
            width: 32px;
            height: 32px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
        }
        .att-icon.vpc { background: #3b82f6; color: white; }
        .att-icon.vpn { background: #22c55e; color: white; }
        .att-icon.dx { background: #a855f7; color: white; }
        .att-name { font-weight: 600; }
        .att-detail { font-size: 0.8rem; color: #666; margin: 0.25rem 0; }
        .att-detail code {
            background: #e9ecef;
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
            font-size: 0.75rem;
        }
        .issue-item {
            padding: 0.75rem 1rem;
            border-radius: 6px;
            margin-bottom: 0.5rem;
            display: flex;
            gap: 0.75rem;
            align-items: flex-start;
        }
        .issue-item.warning { background: #fff3cd; border: 1px solid #ffc107; }
        .issue-item.info { background: #cff4fc; border: 1px solid #0dcaf0; }
        .issue-item.error { background: #fee2e2; border: 1px solid #ef4444; }
        .issue-icon { font-size: 1.2rem; }
        .issue-content { flex: 1; }
        .issue-type { font-weight: 600; font-size: 0.85rem; }
        .issue-message { font-size: 0.85rem; color: #666; }
        .issue-location { font-size: 0.75rem; color: #888; }
        
        /* VPN Connections */
        .vpn-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .vpn-card.all-up { border-left: 4px solid #22c55e; }
        .vpn-card.partial { border-left: 4px solid #f59e0b; }
        .vpn-card.down { border-left: 4px solid #ef4444; }
        .vpn-card-header {
            background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
            color: white;
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .vpn-card.partial .vpn-card-header { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }
        .vpn-card.down .vpn-card-header { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
        .vpn-title { display: flex; align-items: center; gap: 0.5rem; }
        .vpn-title h3 { margin: 0; font-size: 1.1rem; }
        .vpn-status-icon { font-size: 1.2rem; }
        .vpn-tunnel-summary {
            background: rgba(255,255,255,0.2);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        .vpn-badges { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .vpn-feature {
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
        }
        .vpn-feature.accelerated { background: #fef3c7; color: #92400e; }
        .vpn-feature.static { background: #e5e7eb; color: #374151; }
        .vpn-feature.bgp { background: #dbeafe; color: #1e40af; }
        .vpn-connected-to {
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            background: rgba(255,255,255,0.2);
        }
        .vpn-card-body { padding: 1rem 1.25rem; }
        .vpn-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 1rem;
        }
        .vpn-info-section {
            background: #f8fafc;
            padding: 1rem;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }
        .vpn-info-title {
            font-weight: 600;
            font-size: 0.85rem;
            color: #333;
            margin-bottom: 0.75rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #e2e8f0;
        }
        .vpn-info-row {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            padding: 0.25rem 0;
        }
        .vpn-info-row .label { color: #666; }
        .vpn-info-row code { font-size: 0.8rem; }
        .state-badge {
            padding: 0.1rem 0.4rem;
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .state-badge.available { background: #dcfce7; color: #166534; }
        .state-badge.pending { background: #fef3c7; color: #92400e; }
        .state-badge.deleting { background: #fee2e2; color: #991b1b; }
        .vpn-tunnels { margin-top: 1rem; }
        .vpn-tunnels-title {
            font-weight: 600;
            font-size: 0.85rem;
            color: #333;
            margin-bottom: 0.5rem;
        }
        .tunnel-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            overflow: hidden;
        }
        .tunnel-table th {
            background: #f1f5f9;
            padding: 0.5rem 0.75rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.75rem;
            color: #475569;
            text-transform: uppercase;
        }
        .tunnel-table td {
            padding: 0.5rem 0.75rem;
            border-top: 1px solid #e2e8f0;
        }
        .tunnel-row.up { background: rgba(220, 252, 231, 0.3); }
        .tunnel-row.down { background: rgba(254, 226, 226, 0.3); }
        .tunnel-status-badge {
            display: inline-block;
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            font-size: 0.7rem;
            font-weight: 700;
        }
        .tunnel-status-badge.up { background: #dcfce7; color: #166534; }
        .tunnel-status-badge.down { background: #fee2e2; color: #991b1b; }
        .status-msg { font-size: 0.8rem; color: #666; }
        .vpn-mini { font-size: 0.7rem; margin-top: 0.25rem; }
        
        /* Direct Connect */
        .dx-gateways-section {
            background: linear-gradient(135deg, #a855f7 0%, #9333ea 100%);
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            color: white;
        }
        .dx-gateways-section h3 { margin: 0 0 1rem 0; font-size: 1rem; }
        .dx-gw-grid { display: flex; gap: 1rem; flex-wrap: wrap; }
        .dx-gw-card {
            background: rgba(255,255,255,0.15);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .dx-gw-icon { font-size: 1.5rem; }
        .dx-gw-name { font-weight: 600; }
        .dx-gw-details { font-size: 0.8rem; opacity: 0.9; }
        .dx-gw-details code { background: rgba(255,255,255,0.2); padding: 0.1rem 0.3rem; border-radius: 3px; }
        
        .dx-conn-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .dx-conn-card.available { border-left: 4px solid #a855f7; }
        .dx-conn-card.down { border-left: 4px solid #ef4444; }
        .dx-conn-card.other { border-left: 4px solid #f59e0b; }
        .dx-conn-header {
            background: linear-gradient(135deg, #a855f7 0%, #9333ea 100%);
            color: white;
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .dx-conn-card.down .dx-conn-header { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }
        .dx-conn-title { display: flex; align-items: center; gap: 0.5rem; }
        .dx-conn-title h3 { margin: 0; font-size: 1.1rem; }
        .dx-conn-icon { font-size: 1.2rem; }
        .dx-conn-bandwidth {
            background: rgba(255,255,255,0.2);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .dx-conn-meta { display: flex; gap: 1rem; font-size: 0.8rem; flex-wrap: wrap; }
        .dx-conn-info {
            background: #f8fafc;
            padding: 0.75rem 1.25rem;
            display: flex;
            gap: 2rem;
            font-size: 0.85rem;
            border-bottom: 1px solid #e2e8f0;
        }
        .dx-conn-body { padding: 1rem 1.25rem; }
        .vif-section-title {
            font-weight: 600;
            font-size: 0.9rem;
            color: #333;
            margin-bottom: 0.75rem;
        }
        
        .vif-card {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .vif-card.all-up { border-left: 3px solid #22c55e; }
        .vif-card.partial { border-left: 3px solid #f59e0b; }
        .vif-card.down { border-left: 3px solid #ef4444; }
        .vif-header {
            background: white;
            padding: 0.75rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
            border-bottom: 1px solid #e2e8f0;
        }
        .vif-title { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
        .vif-name { font-weight: 600; }
        .vif-status-icon { font-size: 1rem; }
        .vif-type-badge {
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        .vif-type-badge.transit { background: #dbeafe; color: #1e40af; }
        .vif-type-badge.private { background: #dcfce7; color: #166534; }
        .vif-type-badge.public { background: #fef3c7; color: #92400e; }
        .vif-bgp-summary { font-size: 0.8rem; color: #666; }
        .vif-dxgw {
            font-size: 0.8rem;
            background: #f3e8ff;
            color: #7c3aed;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }
        .vif-body { padding: 0.75rem 1rem; }
        .vif-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 0.5rem;
            font-size: 0.85rem;
            margin-bottom: 0.75rem;
        }
        .vif-info-item .label { color: #666; }
        .vif-prefixes {
            font-size: 0.8rem;
            color: #666;
            margin-bottom: 0.75rem;
            padding: 0.5rem;
            background: #f1f5f9;
            border-radius: 4px;
        }
        
        .bgp-section { margin-top: 0.5rem; }
        .bgp-title {
            font-weight: 600;
            font-size: 0.8rem;
            color: #475569;
            margin-bottom: 0.5rem;
        }
        .bgp-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8rem;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
        }
        .bgp-table th {
            background: #f1f5f9;
            padding: 0.4rem 0.6rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.7rem;
            color: #475569;
            text-transform: uppercase;
        }
        .bgp-table td { padding: 0.4rem 0.6rem; border-top: 1px solid #e2e8f0; }
        .bgp-row.up { background: rgba(220, 252, 231, 0.3); }
        .bgp-row.down { background: rgba(254, 226, 226, 0.3); }
        .bgp-status-badge {
            display: inline-block;
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
            font-size: 0.65rem;
            font-weight: 700;
        }
        .bgp-status-badge.up { background: #dcfce7; color: #166534; }
        .bgp-status-badge.down { background: #fee2e2; color: #991b1b; }
        
        /* VPC Details */
        .vpc-card {
            background: #fafafa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        /* VPC Details Card Styling */
        .vpc-details-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        .vpc-details-header {
            background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
            color: white;
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .vpc-details-title { display: flex; align-items: center; gap: 0.75rem; }
        .vpc-details-title h3 { margin: 0; font-size: 1.2rem; font-weight: 600; }
        .vpc-details-title .vpc-id { background: rgba(255,255,255,0.2); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; }
        .vpc-details-badges { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .vpc-cidr-badge { background: rgba(255,255,255,0.25); padding: 0.25rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500; }
        .vpc-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .vpc-badge.igw { background: #dcfce7; color: #166534; }
        .vpc-badge.nat { background: #dbeafe; color: #1e40af; }
        .vpc-badge.tgw { background: #fef3c7; color: #92400e; }
        .vpc-details-stats {
            background: #f8fafc;
            padding: 0.5rem 1.25rem;
            display: flex;
            gap: 1.5rem;
            font-size: 0.85rem;
            color: #64748b;
            border-bottom: 1px solid #e0e0e0;
        }
        .vpc-details-body { padding: 1rem; }
        
        /* Route Table Section */
        .rt-section {
            background: #fafafa;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .rt-section:last-child { margin-bottom: 0; }
        .rt-section-header {
            background: #374151;
            color: white;
            padding: 0.6rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .rt-section-title { display: flex; align-items: center; gap: 0.5rem; font-weight: 500; }
        .rt-icon { font-size: 1rem; }
        .rt-name { font-weight: 600; }
        .badge-main { background: #fbbf24; color: #78350f; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.65rem; font-weight: 700; }
        .default-route { margin-left: 0.75rem; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.7rem; font-weight: 500; }
        .default-route.igw { background: #22c55e; color: white; }
        .default-route.nat { background: #3b82f6; color: white; }
        .default-route.tgw { background: #f59e0b; color: white; }
        .default-route.other { background: #6b7280; color: white; }
        .rt-section-meta { display: flex; align-items: center; gap: 1rem; font-size: 0.75rem; opacity: 0.8; }
        .subnet-count { background: rgba(255,255,255,0.2); padding: 0.1rem 0.4rem; border-radius: 3px; }
        
        /* Subnet Table */
        .subnet-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        .subnet-table th {
            background: #f1f5f9;
            text-align: left;
            padding: 0.5rem 0.75rem;
            font-weight: 600;
            color: #475569;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.025em;
            border-bottom: 1px solid #e2e8f0;
        }
        .subnet-table td {
            padding: 0.6rem 0.75rem;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: middle;
        }
        .subnet-table tr:last-child td { border-bottom: none; }
        .subnet-row.public { background: #f0fdf4; }
        .subnet-row.private { background: #eff6ff; }
        .subnet-row.tgw { background: #fffbeb; }
        .subnet-row.isolated { background: #f9fafb; }
        .subnet-type-badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        .subnet-type-badge.public { background: #22c55e; color: white; }
        .subnet-type-badge.private { background: #3b82f6; color: white; }
        .subnet-type-badge.tgw { background: #f59e0b; color: white; }
        .subnet-type-badge.isolated { background: #6b7280; color: white; }
        .subnet-legend {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem 1.5rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        .legend-title { font-weight: 600; color: #475569; }
        .legend-desc { font-size: 0.8rem; color: #64748b; margin-right: 1rem; }
        .subnet-name-cell { font-weight: 500; color: #1e293b; }
        .subnet-cidr-cell code { background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.8rem; }
        .subnet-az-cell { color: #64748b; }
        .subnet-id-cell code { font-size: 0.75rem; color: #64748b; }
        
        /* Route Table Body Layout */
        .rt-section-body { padding: 1rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        @media (max-width: 1200px) { .rt-section-body { grid-template-columns: 1fr; } }
        .subnets-section, .routes-section { background: white; border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden; }
        .subnets-title, .routes-title {
            background: #f8fafc;
            padding: 0.5rem 0.75rem;
            font-weight: 600;
            font-size: 0.8rem;
            color: #475569;
            border-bottom: 1px solid #e2e8f0;
        }
        
        /* Routes Table */
        .routes-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        .routes-table th {
            background: #f8fafc;
            padding: 0.5rem 0.75rem;
            text-align: left;
            font-weight: 600;
            color: #64748b;
            font-size: 0.75rem;
            text-transform: uppercase;
            border-bottom: 1px solid #e2e8f0;
        }
        .routes-table td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #f1f5f9; }
        .routes-table tr:last-child td { border-bottom: none; }
        .routes-table code { font-size: 0.8rem; }
        .route-local { background: #f8fafc; }
        .route-local td { color: #94a3b8; }
        .route-igw { background: #f0fdf4; }
        .route-igw td:nth-child(2) { color: #16a34a; font-weight: 500; }
        .route-nat { background: #eff6ff; }
        .route-nat td:nth-child(2) { color: #2563eb; font-weight: 500; }
        .route-tgw { background: #fffbeb; }
        .route-tgw td:nth-child(2) { color: #d97706; font-weight: 500; }
        
        /* Keep old styles for compatibility */
        .vpc-card-header {
            background: #3b82f6;
            color: white;
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .vpc-card-header h3 { margin: 0; font-size: 1.1rem; }
        .vpc-card-header .vpc-cidr { font-size: 0.85rem; opacity: 0.9; }
        .vpc-card-body { padding: 1rem; }
        .vpc-section { margin-bottom: 1rem; }
        .vpc-section:last-child { margin-bottom: 0; }
        .vpc-section-title {
            font-weight: 600;
            font-size: 0.85rem;
            color: #333;
            margin-bottom: 0.5rem;
            padding-bottom: 0.25rem;
            border-bottom: 1px solid #e0e0e0;
        }
        .subnet-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 0.75rem;
        }
        .subnet-item {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 0.75rem;
            font-size: 0.85rem;
        }
        .subnet-item.public { border-left: 3px solid #22c55e; }
        .subnet-item.private { border-left: 3px solid #3b82f6; }
        .subnet-item.isolated { border-left: 3px solid #6b7280; }
        .subnet-item.tgw { border-left: 3px solid #f59e0b; }
        .subnet-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        .subnet-name { font-weight: 600; color: #333; }
        .subnet-type {
            font-size: 0.7rem;
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            text-transform: uppercase;
            font-weight: 600;
        }
        .subnet-type.public { background: #dcfce7; color: #166534; }
        .subnet-type.private { background: #dbeafe; color: #1e40af; }
        .subnet-type.isolated { background: #f3f4f6; color: #374151; }
        .subnet-type.tgw { background: #fef3c7; color: #92400e; }
        .subnet-details { color: #666; font-size: 0.8rem; }
        .subnet-details div { margin-bottom: 0.2rem; }
        .rt-list {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .rt-chip {
            background: #e5e7eb;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            color: #333;
        }
        .rt-chip.main { background: #dbeafe; color: #1e40af; }
        
        /* Print Styles */
        @media print {
            body { font-size: 10pt; }
            .header { padding: 0.5rem 1rem; }
            .tabs, .issues-banner { display: none; }
            .tab-content { display: block !important; page-break-inside: avoid; }
            .diagram-container { max-height: none; overflow: visible; }
            .mermaid { transform: scale(0.8); transform-origin: top left; }
            .vpn-card, .vpc-details-card, .route-table { page-break-inside: avoid; }
            .report-footer { display: none; }
        }
        
        /* Footer */
        .report-footer {
            background: #232f3e;
            color: #aaa;
            padding: 1rem 2rem;
            text-align: center;
            font-size: 0.8rem;
            margin-top: 2rem;
        }
        .report-footer a { color: #ff9900; text-decoration: none; }
        .report-footer a:hover { text-decoration: underline; }
        '''
    
    def _get_account_mode_badge(self) -> str:
        """Generate hub/spoke mode badge for header."""
        if self.data.is_hub_account:
            return '<span class="mode-badge hub">Hub Account</span>'
        elif self.data.is_spoke_account:
            return '<span class="mode-badge spoke">Spoke Account</span>'
        return ''
    
    def _get_tgw_reference(self) -> str:
        """Generate TGW reference for spoke accounts."""
        if self.data.is_spoke_account and self.data.referenced_tgw_ids:
            tgw_ids = ", ".join(sorted(self.data.referenced_tgw_ids))
            return f' | TGW: <code>{tgw_ids}</code>'
        return ''
    
    def _get_spoke_guidance_banner(self) -> str:
        """Generate guidance banner for spoke accounts."""
        if not self.data.is_spoke_account:
            return ''
        return '''
    <div class="spoke-guidance-banner">
        <strong>📍 Spoke Account View</strong> - You are viewing from a spoke account with limited TGW visibility. 
        TGW route tables are only visible from the hub/network account that owns the Transit Gateway.
        This view shows your local VPCs, subnets, and TGW attachments.
    </div>'''
    
    def _vpn_tab_button(self) -> str:
        """Generate VPN tab button if VPN connections exist."""
        if not self.data.vpn_connections:
            return ""
        return f'<button class="tab" onclick="showTab(\'vpn-tab\')">VPN ({len(self.data.vpn_connections)})</button>'
    
    def _vpn_tab_content(self) -> str:
        """Generate VPN tab content if VPN connections exist."""
        if not self.data.vpn_connections:
            return ""
        return f'<div id="vpn-tab" class="tab-content">{self._generate_vpn_html()}</div>'
    
    def _dx_tab_button(self) -> str:
        """Generate DX tab button if DX VIFs exist."""
        if not self.data.dx_vifs:
            return ""
        return f'<button class="tab" onclick="showTab(\'dx-tab\')">Direct Connect ({len(self.data.dx_vifs)})</button>'
    
    def _dx_tab_content(self) -> str:
        """Generate DX tab content if DX VIFs exist."""
        if not self.data.dx_vifs:
            return ""
        return f'<div id="dx-tab" class="tab-content">{self._generate_dx_html()}</div>'
    
    def _generate_stats_bar(self) -> str:
        tgw_count = len(self.data.tgws)
        vpc_count = len(self.data.vpcs)
        att_count = len(self.data.tgw_attachments)
        rt_count = len(self.data.tgw_route_tables)
        subnet_count = len(self.data.subnets)
        cross_account_count = len(self.data.cross_account_attachments)
        vpn_count = len(self.data.vpn_connections)
        dx_vif_count = len(self.data.dx_vifs)
        
        # Count subnets by type
        subnet_types = {"public": 0, "private": 0, "tgw": 0, "isolated": 0}
        for s in self.data.subnets.values():
            subnet_types[s.subnet_type.value] = subnet_types.get(s.subnet_type.value, 0) + 1
        
        cross_account_html = ""
        if cross_account_count > 0:
            cross_account_html = f'<div class="stat"><div class="stat-value" style="color:#e67e22;">{cross_account_count}</div><div class="stat-label">Cross-Account</div></div>'
        
        # VPN stats with tunnel status
        vpn_html = ""
        if vpn_count > 0:
            tunnels_up = sum(1 for v in self.data.vpn_connections.values() for t in v.tunnels if t.status == "UP")
            tunnels_total = sum(len(v.tunnels) for v in self.data.vpn_connections.values())
            tunnel_color = "#22c55e" if tunnels_up == tunnels_total else ("#f59e0b" if tunnels_up > 0 else "#ef4444")
            vpn_html = f'''<div class="stat">
                <div class="stat-value" style="color:#22c55e;">{vpn_count}</div>
                <div class="stat-label">VPN Connections</div>
                <div class="vpn-mini" style="color:{tunnel_color};">{tunnels_up}/{tunnels_total} tunnels UP</div>
            </div>'''
        
        # DX stats with BGP status
        dx_html = ""
        if dx_vif_count > 0:
            bgp_up = sum(1 for v in self.data.dx_vifs.values() for p in v.bgp_peers if p.bgp_status.lower() == "up")
            bgp_total = sum(len(v.bgp_peers) for v in self.data.dx_vifs.values())
            bgp_color = "#a855f7" if bgp_up == bgp_total else ("#f59e0b" if bgp_up > 0 else "#ef4444")
            dx_html = f'''<div class="stat">
                <div class="stat-value" style="color:#a855f7;">{dx_vif_count}</div>
                <div class="stat-label">DX VIFs</div>
                <div class="vpn-mini" style="color:{bgp_color};">{bgp_up}/{bgp_total} BGP UP</div>
            </div>'''
        
        # Subnet mini-breakdown
        subnet_mini = f'''
        <div class="subnet-mini">
            <span class="subnet-mini-item public">{subnet_types["public"]} pub</span>
            <span class="subnet-mini-item private">{subnet_types["private"]} priv</span>
            <span class="subnet-mini-item tgw">{subnet_types["tgw"]} tgw</span>
            <span class="subnet-mini-item isolated">{subnet_types["isolated"]} iso</span>
        </div>'''
        
        return f'''
        <div class="stat"><div class="stat-value">{tgw_count}</div><div class="stat-label">Transit Gateways</div></div>
        <div class="stat"><div class="stat-value">{att_count}</div><div class="stat-label">TGW Attachments</div></div>
        {cross_account_html}
        {vpn_html}
        {dx_html}
        <div class="stat"><div class="stat-value">{rt_count}</div><div class="stat-label">TGW Route Tables</div></div>
        <div class="stat"><div class="stat-value">{vpc_count}</div><div class="stat-label">Local VPCs</div></div>
        <div class="stat">
            <div class="stat-value">{subnet_count}</div>
            <div class="stat-label">Subnets</div>
            {subnet_mini}
        </div>
        '''
    
    def _generate_issues_banner(self, issues: list) -> str:
        count = len(issues)
        return f'<div class="issues-banner">⚠️ {count} issue{"s" if count != 1 else ""} detected - see Issues tab for details</div>'
    
    def _generate_mermaid(self) -> str:
        lines = ["flowchart TB"]
        lines.append("")
        
        # Styles
        lines.append("    classDef tgw fill:#ff9900,stroke:#232f3e,color:#232f3e")
        lines.append("    classDef tgwrt fill:#232f3e,stroke:#232f3e,color:#fff")
        lines.append("    classDef vpc fill:#3b82f6,stroke:#1e40af,color:#fff")
        lines.append("    classDef vpcCrossAcct fill:#e67e22,stroke:#d35400,color:#fff")
        lines.append("    classDef vpn fill:#22c55e,stroke:#166534,color:#fff")
        lines.append("    classDef dx fill:#a855f7,stroke:#7c3aed,color:#fff")
        lines.append("    classDef tgwExternal fill:#ff9900,stroke:#232f3e,color:#232f3e,stroke-dasharray: 5 5")
        lines.append("")
        
        # Initialize link tracking
        self._vpc_link_colors = []
        self._non_vpc_link_colors = []
        self._tgw_internal_link_count = 0
        
        # Check if this is a spoke account
        if self.data.is_spoke_account:
            self._generate_spoke_diagram(lines)
        else:
            # Hub account - normal flow
            # TGW section
            for tgw in self.data.tgws.values():
                self._add_tgw_to_mermaid(lines, tgw)
            
            # VPC connections
            self._add_vpc_connections(lines)
            
            # Non-VPC attachments
            self._add_non_vpc_attachments(lines)
        
        # Add link styles - links are numbered in order of appearance
        # First come TGW internal links (TGW node to route tables)
        link_idx = self._tgw_internal_link_count
        
        # VPC links
        for color in self._vpc_link_colors:
            lines.append(f'    linkStyle {link_idx} stroke:{color},stroke-width:2px')
            link_idx += 1
        
        # Non-VPC links
        for color in self._non_vpc_link_colors:
            lines.append(f'    linkStyle {link_idx} stroke:{color},stroke-width:2px')
            link_idx += 1
        
        return "\n".join(lines)
    
    def _generate_spoke_diagram(self, lines: list):
        """Generate diagram for spoke accounts (no TGW visibility)."""
        # Get the referenced TGW ID(s)
        tgw_ids = sorted(self.data.referenced_tgw_ids)
        
        # Create a placeholder TGW subgraph for each referenced TGW
        for tgw_id in tgw_ids:
            safe_tgw_id = self._safe_id(tgw_id)
            lines.append(f'    subgraph TGW_{safe_tgw_id}["Transit Gateway (External)"]')
            lines.append(f'        TGW_NODE_{safe_tgw_id}(("{tgw_id}<br/><small>Route tables not visible<br/>from spoke account</small>"))')
            lines.append(f'        class TGW_NODE_{safe_tgw_id} tgwExternal')
            lines.append("    end")
            lines.append("")
        
        # Add local VPCs
        for vpc in self.data.vpcs.values():
            vpc_safe_id = self._safe_id(vpc.id)
            cidrs = ", ".join(vpc.cidrs[:2]) if vpc.cidrs else "CIDR unknown"
            name = vpc.name if vpc.name else vpc.id[:20]
            
            # Features
            features = []
            if vpc.igw_id:
                features.append("IGW")
            if vpc.nat_gateway_ids:
                features.append("NAT")
            if vpc.tgw_attachment_id:
                features.append("TGW")
            feature_str = f"<br/><small>{' | '.join(features)}</small>" if features else ""
            
            lines.append(f'    VPC_{vpc_safe_id}["{html.escape(name)}<br/><small>{cidrs}</small>{feature_str}"]')
            lines.append(f'    class VPC_{vpc_safe_id} vpc')
        
        # Connect VPCs to the external TGW via their attachments
        for att in self.data.tgw_attachments.values():
            if att.type == AttachmentType.VPC and att.resource_id in self.data.vpcs:
                vpc_safe_id = self._safe_id(att.resource_id)
                tgw_safe_id = self._safe_id(att.tgw_id)
                lines.append(f'    VPC_{vpc_safe_id} --> TGW_NODE_{tgw_safe_id}')
                self._vpc_link_colors.append("#93c5fd")  # Pastel blue
        
        lines.append("")
    
    def _add_tgw_to_mermaid(self, lines: list, tgw: TransitGateway):
        tgw_id = self._safe_id(tgw.id)
        lines.append(f'    subgraph TGW_{tgw_id}["{tgw.name}"]')
        lines.append(f'        TGW_NODE_{tgw_id}(("{tgw.name}"))')
        lines.append(f'        class TGW_NODE_{tgw_id} tgw')
        
        # Route tables
        for rt in self.data.tgw_route_tables.values():
            if rt.tgw_id != tgw.id:
                continue
            
            rt_id = self._safe_id(rt.id)
            default = " ⭐" if rt.is_default_association else ""
            
            # Associated attachments - handle empty names
            assoc_names = []
            for att_id in rt.associations:
                if att_id in self.data.tgw_attachments:
                    att = self.data.tgw_attachments[att_id]
                    name = att.name if att.name else att.id[:15]
                    assoc_names.append(name)
            assoc_str = ", ".join(assoc_names[:3])
            if len(assoc_names) > 3:
                assoc_str += f" +{len(assoc_names)-3}"
            
            # Routes summary
            route_lines = []
            for route in rt.routes[:5]:
                state = "🕳️" if route.is_blackhole else "✓"
                rtype = "P" if route.route_type == RouteType.PROPAGATED else "S"
                dest = route.destination[:18]
                
                target = "blackhole"
                res_type = ""
                if route.attachment_id and route.attachment_id in self.data.tgw_attachments:
                    att = self.data.tgw_attachments[route.attachment_id]
                    target = (att.name if att.name else att.id)[:15]
                    res_type = att.type.value.upper()[:3]
                
                route_lines.append(f"{state} {dest} → {target} [{res_type}] [{rtype}]")
            
            if len(rt.routes) > 5:
                route_lines.append(f"... +{len(rt.routes)-5} more")
            
            routes_str = "<br/>".join(route_lines)
            
            # Handle empty route table name
            rt_name = rt.name if rt.name else rt.id
            label = f"<b>{html.escape(rt_name)}{default}</b>"
            if assoc_str:
                label += f"<br/><small>Assoc: {html.escape(assoc_str)}</small>"
            label += f"<br/><small>{routes_str}</small>"
            
            lines.append(f'        TGWRT_{rt_id}["{label}"]')
            lines.append(f'        class TGWRT_{rt_id} tgwrt')
            lines.append(f'        TGW_NODE_{tgw_id} --- TGWRT_{rt_id}')
            self._tgw_internal_link_count += 1  # Count internal link
        
        lines.append("    end")
        lines.append("")
    
    def _add_vpc_connections(self, lines: list):
        link_index = 0  # Track link index for styling
        vpc_links = []  # Store link info for styling
        
        for att in self.data.tgw_attachments.values():
            if att.type == AttachmentType.VPC:
                vpc_id = self._safe_id(att.resource_id)
                
                # Check if we have full VPC details (local VPC) or just attachment info (cross-account)
                if att.resource_id in self.data.vpcs:
                    # Local VPC - we have full details
                    vpc = self.data.vpcs[att.resource_id]
                    cidrs = ", ".join(vpc.cidrs[:2]) if vpc.cidrs else "CIDR unknown"
                    # Handle empty name - use VPC ID
                    name = vpc.name if vpc.name else vpc.id[:20]
                    style_class = "vpc"
                    link_color = "#93c5fd"  # Pastel blue for local VPC lines
                else:
                    # Cross-account VPC - use attachment info
                    cidrs = ", ".join(att.cidrs[:2]) if att.cidrs else "CIDR unknown"
                    # Handle empty name - use VPC ID or attachment name
                    if att.name and att.name != att.resource_id:
                        name = att.name
                    else:
                        name = att.resource_id[:20] + "..."
                    style_class = "vpcCrossAcct"
                    link_color = "#fcd34d"  # Light gold for cross-account lines
                
                # Add account badge for cross-account
                account_info = ""
                if att.is_cross_account:
                    account_info = f"<br/><small>🔗 Acct: ...{att.resource_owner_id[-4:]}</small>"
                    style_class = "vpcCrossAcct"
                    link_color = "#fcd34d"  # Light gold for cross-account lines
                
                lines.append(f'    VPC_{vpc_id}["{html.escape(name)}<br/><small>{cidrs}</small>{account_info}"]')
                lines.append(f'    class VPC_{vpc_id} {style_class}')
                
                if att.associated_route_table_id:
                    rt_id = self._safe_id(att.associated_route_table_id)
                    lines.append(f'    VPC_{vpc_id} --> TGWRT_{rt_id}')
                    vpc_links.append(link_color)
        
        # Add link styles for VPC connections
        # Note: We need to count all previous links (TGW to RT connections) first
        # This is handled in the main mermaid generation
        lines.append("")
        
        # Store link colors for later styling
        self._vpc_link_colors = vpc_links
    
    def _add_non_vpc_attachments(self, lines: list):
        non_vpc_links = []
        
        for att in self.data.tgw_attachments.values():
            if att.type != AttachmentType.VPC:
                att_id = self._safe_id(att.id)
                type_label = att.type.value.upper()
                
                # Handle empty name
                name = att.name if att.name else att.id[:20]
                
                lines.append(f'    ATT_{att_id}["{html.escape(name)}<br/><small>{type_label}</small>"]')
                
                if att.type == AttachmentType.VPN:
                    lines.append(f'    class ATT_{att_id} vpn')
                    link_color = "#86efac"  # Pastel green for VPN lines
                else:
                    lines.append(f'    class ATT_{att_id} dx')
                    link_color = "#d8b4fe"  # Pastel purple for DX lines
                
                if att.associated_route_table_id:
                    rt_id = self._safe_id(att.associated_route_table_id)
                    lines.append(f'    ATT_{att_id} --> TGWRT_{rt_id}')
                    non_vpc_links.append(link_color)
        
        lines.append("")
        self._non_vpc_link_colors = non_vpc_links
    
    def _safe_id(self, s: str) -> str:
        return s.replace("-", "_").replace(".", "_").replace("/", "_")
    
    def _generate_tgw_tables_html(self) -> str:
        html_parts = []
        
        for rt in self.data.tgw_route_tables.values():
            badges = []
            if rt.is_default_association:
                badges.append('<span class="badge">Default Association</span>')
            if rt.is_default_propagation:
                badges.append('<span class="badge">Default Propagation</span>')
            
            # Get associated attachment names
            assoc_names = [self.data.tgw_attachments[a].name for a in rt.associations if a in self.data.tgw_attachments]
            prop_names = [self.data.tgw_attachments[a].name for a in rt.propagations if a in self.data.tgw_attachments]
            
            meta = []
            meta.append(f"<strong>ID:</strong> {rt.id}")
            if assoc_names:
                meta.append(f"<strong>Associated:</strong> {', '.join(assoc_names)}")
            if prop_names:
                meta.append(f"<strong>Propagations:</strong> {', '.join(prop_names)}")
            
            rows = ""
            for route in rt.routes:
                state_class = "state-blackhole" if route.is_blackhole else "state-active"
                state_text = "blackhole" if route.is_blackhole else "active"
                route_type = "propagated" if route.route_type == RouteType.PROPAGATED else "static"
                
                att_id = route.attachment_id or "-"
                resource_id = route.resource_id or "-"
                resource_type = route.resource_type or "-"
                
                # Get friendly name and account info
                target_name = "-"
                owner_account = "-"
                owner_style = ""
                if route.attachment_id and route.attachment_id in self.data.tgw_attachments:
                    att = self.data.tgw_attachments[route.attachment_id]
                    target_name = att.name if att.name else att.resource_id
                    if att.resource_owner_id:
                        owner_account = f"...{att.resource_owner_id[-4:]}"
                        if att.is_cross_account:
                            owner_style = 'style="color:#e67e22;font-weight:600;"'
                            owner_account = f"🔗 {att.resource_owner_id}"
                
                rows += f'''
                <tr>
                    <td class="{state_class}">{state_text}</td>
                    <td>{route.destination}</td>
                    <td>{att_id}</td>
                    <td>{target_name}</td>
                    <td {owner_style}>{owner_account}</td>
                    <td>{resource_type}</td>
                    <td><span class="route-type">{route_type}</span></td>
                </tr>'''
            
            html_parts.append(f'''
            <div class="route-table-card">
                <div class="route-table-header">
                    <span>{html.escape(rt.name)}</span>
                    <span>{" ".join(badges)}</span>
                </div>
                <div class="route-table-meta">{" &nbsp;|&nbsp; ".join(meta)}</div>
                <table>
                    <thead>
                        <tr>
                            <th>State</th>
                            <th>CIDR / Prefix List</th>
                            <th>Attachment ID</th>
                            <th>Target Name</th>
                            <th>Owner Account</th>
                            <th>Resource Type</th>
                            <th>Route Type</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>''')
        
        return "".join(html_parts) if html_parts else "<p>No TGW route tables found.</p>"
    
    def _generate_attachments_html(self) -> str:
        cards = []
        
        # Sort: cross-account first, then by type, then by name (handle empty)
        sorted_atts = sorted(
            self.data.tgw_attachments.values(),
            key=lambda a: (not a.is_cross_account, a.type.value, a.name or a.id)
        )
        
        for att in sorted_atts:
            icon_class = "vpc" if att.type == AttachmentType.VPC else ("vpn" if att.type == AttachmentType.VPN else "dx")
            icon = "🔷" if att.type == AttachmentType.VPC else ("🔒" if att.type == AttachmentType.VPN else "⚡")
            
            cidrs = ", ".join(att.cidrs) if att.cidrs else "<em>Not visible (cross-account)</em>"
            
            # Handle association/propagation - may not be visible from spoke accounts
            if att.associated_route_table_id:
                assoc_rt = f'<code>{att.associated_route_table_id}</code>'
            elif self.data.is_spoke_account:
                assoc_rt = '<em>Not visible from spoke account</em>'
            else:
                assoc_rt = '<em>Not associated</em>'
            
            if att.propagating_to:
                props = ", ".join(att.propagating_to)
            elif self.data.is_spoke_account:
                props = '<em>Not visible from spoke account</em>'
            else:
                props = '<em>Not propagating</em>'
            
            # Handle empty name - use resource ID
            display_name = att.name if att.name else att.resource_id
            
            # Cross-account badge and styling
            cross_account_badge = ""
            card_style = ""
            if att.is_cross_account:
                cross_account_badge = '<span style="background:#e67e22;color:white;padding:0.15rem 0.4rem;border-radius:3px;font-size:0.7rem;margin-left:0.5rem;">CROSS-ACCOUNT</span>'
                card_style = "border-left: 3px solid #e67e22;"
                icon_class = "vpc" if att.type == AttachmentType.VPC else icon_class  # Keep icon but note cross-account
            
            # Account info row
            account_row = ""
            if att.resource_owner_id:
                local_badge = "" if att.is_cross_account else ' <span style="color:#27ae60;font-size:0.7rem;">(local)</span>'
                account_row = f'<div class="att-detail"><strong>Owner Account:</strong> <code>{att.resource_owner_id}</code>{local_badge}</div>'
            
            cards.append(f'''
            <div class="att-card" style="{card_style}">
                <div class="att-card-header">
                    <div class="att-icon {icon_class}">{icon}</div>
                    <div>
                        <div class="att-name">{html.escape(display_name)}{cross_account_badge}</div>
                        <div style="font-size: 0.75rem; color: #888;">{att.type.value.upper()}</div>
                    </div>
                </div>
                <div class="att-detail"><strong>Attachment ID:</strong> <code>{att.id}</code></div>
                <div class="att-detail"><strong>Resource ID:</strong> <code>{att.resource_id}</code></div>
                {account_row}
                <div class="att-detail"><strong>CIDRs:</strong> {cidrs}</div>
                <div class="att-detail"><strong>Associated RT:</strong> {assoc_rt}</div>
                <div class="att-detail"><strong>Propagates to:</strong> {props}</div>
                <div class="att-detail"><strong>State:</strong> {att.state}</div>
            </div>''')
        
        return f'<div class="attachment-card">{"".join(cards)}</div>' if cards else "<p>No attachments found.</p>"
    
    def _generate_vpn_html(self) -> str:
        """Generate VPN connections display."""
        if not self.data.vpn_connections:
            return "<p>No VPN connections found.</p>"
        
        cards = []
        
        for vpn in sorted(self.data.vpn_connections.values(), key=lambda v: v.name):
            # Get customer gateway info
            cgw = self.data.customer_gateways.get(vpn.customer_gateway_id)
            cgw_name = cgw.name if cgw else vpn.customer_gateway_id
            cgw_ip = cgw.ip_address if cgw else "Unknown"
            cgw_asn = cgw.bgp_asn if cgw else "Unknown"
            cgw_device = cgw.device_name if cgw and cgw.device_name else "Not specified"
            
            # Tunnel status
            tunnel_status = vpn.tunnel_status
            status_class = "all-up" if tunnel_status == "all_up" else ("partial" if tunnel_status == "partial" else "down")
            status_icon = "✅" if tunnel_status == "all_up" else ("⚠️" if tunnel_status == "partial" else "❌")
            
            # Build tunnel rows
            tunnel_rows = []
            for i, tunnel in enumerate(vpn.tunnels):
                t_status_class = "up" if tunnel.status == "UP" else "down"
                t_icon = "🟢" if tunnel.status == "UP" else "🔴"
                status_msg = tunnel.status_message if tunnel.status_message else "-"
                tunnel_rows.append(f'''
                <tr class="tunnel-row {t_status_class}">
                    <td>{t_icon} Tunnel {i+1}</td>
                    <td><code>{tunnel.outside_ip}</code></td>
                    <td><span class="tunnel-status-badge {t_status_class}">{tunnel.status}</span></td>
                    <td>{tunnel.accepted_route_count}</td>
                    <td class="status-msg">{html.escape(status_msg)}</td>
                </tr>''')
            
            tunnels_html = f'''
            <table class="tunnel-table">
                <thead>
                    <tr>
                        <th>Tunnel</th>
                        <th>Outside IP</th>
                        <th>Status</th>
                        <th>Routes</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>{"".join(tunnel_rows)}</tbody>
            </table>'''
            
            # Features badges
            features = []
            if vpn.enable_acceleration:
                features.append('<span class="vpn-feature accelerated">⚡ Accelerated</span>')
            if vpn.static_routes_only:
                features.append('<span class="vpn-feature static">📌 Static Routes</span>')
            else:
                features.append('<span class="vpn-feature bgp">🔄 BGP</span>')
            features_html = " ".join(features)
            
            # Connected to (TGW or VGW)
            connected_to = ""
            if vpn.tgw_id:
                tgw = self.data.tgws.get(vpn.tgw_id)
                tgw_name = tgw.name if tgw else vpn.tgw_id
                connected_to = f'<span class="vpn-connected-to tgw">🔗 TGW: {html.escape(tgw_name)}</span>'
            elif vpn.vpn_gateway_id:
                connected_to = f'<span class="vpn-connected-to vgw">🔗 VGW: {vpn.vpn_gateway_id}</span>'
            
            cards.append(f'''
            <div class="vpn-card {status_class}">
                <div class="vpn-card-header">
                    <div class="vpn-title">
                        <span class="vpn-status-icon">{status_icon}</span>
                        <h3>{html.escape(vpn.name)}</h3>
                        <span class="vpn-tunnel-summary">{vpn.tunnel_summary}</span>
                    </div>
                    <div class="vpn-badges">
                        {features_html}
                        {connected_to}
                    </div>
                </div>
                <div class="vpn-card-body">
                    <div class="vpn-info-grid">
                        <div class="vpn-info-section">
                            <div class="vpn-info-title">VPN Connection</div>
                            <div class="vpn-info-row"><span class="label">Connection ID:</span> <code>{vpn.id}</code></div>
                            <div class="vpn-info-row"><span class="label">State:</span> <span class="state-badge {vpn.state}">{vpn.state}</span></div>
                            <div class="vpn-info-row"><span class="label">Local CIDR:</span> <code>{vpn.local_cidr}</code></div>
                            <div class="vpn-info-row"><span class="label">Remote CIDR:</span> <code>{vpn.remote_cidr}</code></div>
                        </div>
                        <div class="vpn-info-section">
                            <div class="vpn-info-title">Customer Gateway</div>
                            <div class="vpn-info-row"><span class="label">Name:</span> {html.escape(cgw_name)}</div>
                            <div class="vpn-info-row"><span class="label">IP Address:</span> <code>{cgw_ip}</code></div>
                            <div class="vpn-info-row"><span class="label">BGP ASN:</span> <code>{cgw_asn}</code></div>
                            <div class="vpn-info-row"><span class="label">Device:</span> {html.escape(cgw_device)}</div>
                        </div>
                    </div>
                    <div class="vpn-tunnels">
                        <div class="vpn-tunnels-title">IPsec Tunnels</div>
                        {tunnels_html}
                    </div>
                </div>
            </div>''')
        
        return "".join(cards)
    
    def _generate_dx_html(self) -> str:
        """Generate Direct Connect display."""
        if not self.data.dx_vifs:
            return "<p>No Direct Connect Virtual Interfaces found.</p>"
        
        # Group VIFs by connection
        vifs_by_conn = defaultdict(list)
        for vif in self.data.dx_vifs.values():
            vifs_by_conn[vif.connection_id].append(vif)
        
        cards = []
        
        # DX Gateway summary if present
        if self.data.dx_gateways:
            gw_cards = []
            for gw in self.data.dx_gateways.values():
                state_class = "available" if gw.state == "available" else "other"
                gw_cards.append(f'''
                <div class="dx-gw-card">
                    <div class="dx-gw-icon">🌐</div>
                    <div class="dx-gw-info">
                        <div class="dx-gw-name">{html.escape(gw.name)}</div>
                        <div class="dx-gw-details">
                            <code>{gw.id}</code> • ASN {gw.amazon_asn} • 
                            <span class="state-badge {state_class}">{gw.state}</span>
                        </div>
                    </div>
                </div>''')
            cards.append(f'''
            <div class="dx-gateways-section">
                <h3>Direct Connect Gateways</h3>
                <div class="dx-gw-grid">{"".join(gw_cards)}</div>
            </div>''')
        
        # Connection cards
        for conn_id, vifs in sorted(vifs_by_conn.items()):
            conn = self.data.dx_connections.get(conn_id)
            if conn:
                conn_name = conn.name
                conn_state = conn.state
                conn_location = conn.location
                conn_bandwidth = conn.bandwidth
                conn_provider = conn.provider_name or conn.partner_name or "Direct"
                conn_redundancy = "✓ Redundant" if conn.has_logical_redundancy else "Single"
            else:
                conn_name = conn_id
                conn_state = "unknown"
                conn_location = ""
                conn_bandwidth = ""
                conn_provider = ""
                conn_redundancy = ""
            
            # Connection status
            state_class = "available" if conn_state == "available" else ("down" if conn_state == "down" else "other")
            state_icon = "✅" if conn_state == "available" else ("❌" if conn_state == "down" else "⚠️")
            
            # Build VIF cards
            vif_cards = []
            for vif in sorted(vifs, key=lambda v: v.name):
                # VIF status
                vif_state_class = "available" if vif.state == "available" else "down"
                vif_state_icon = "✅" if vif.state == "available" else "❌"
                
                # BGP status
                bgp_status = vif.bgp_status
                bgp_class = "all-up" if bgp_status == "all_up" else ("partial" if bgp_status == "partial" else "down")
                bgp_icon = "🟢" if bgp_status == "all_up" else ("🟡" if bgp_status == "partial" else "🔴")
                
                # VIF type badge
                vif_type_class = vif.vif_type
                vif_type_label = vif.vif_type.upper()
                
                # Build BGP peer rows
                bgp_rows = []
                for peer in vif.bgp_peers:
                    peer_status_class = "up" if peer.bgp_status.lower() == "up" else "down"
                    peer_icon = "🟢" if peer.bgp_status.lower() == "up" else "🔴"
                    bgp_rows.append(f'''
                    <tr class="bgp-row {peer_status_class}">
                        <td>{peer_icon} ASN {peer.asn}</td>
                        <td><code>{peer.customer_address}</code></td>
                        <td><code>{peer.amazon_address}</code></td>
                        <td><span class="bgp-status-badge {peer_status_class}">{peer.bgp_status.upper()}</span></td>
                    </tr>''')
                
                bgp_table = ""
                if bgp_rows:
                    bgp_table = f'''
                    <div class="bgp-section">
                        <div class="bgp-title">BGP Peers ({vif.bgp_summary})</div>
                        <table class="bgp-table">
                            <thead>
                                <tr>
                                    <th>Peer ASN</th>
                                    <th>Customer Address</th>
                                    <th>Amazon Address</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>{"".join(bgp_rows)}</tbody>
                        </table>
                    </div>'''
                
                # DX Gateway info
                dxgw_info = ""
                if vif.dx_gateway_id:
                    dxgw = self.data.dx_gateways.get(vif.dx_gateway_id)
                    dxgw_name = dxgw.name if dxgw else vif.dx_gateway_id
                    dxgw_info = f'<span class="vif-dxgw">🔗 {html.escape(dxgw_name)}</span>'
                
                # Route prefixes for public VIFs
                prefixes_html = ""
                if vif.route_filter_prefixes:
                    prefix_list = ", ".join(vif.route_filter_prefixes[:5])
                    if len(vif.route_filter_prefixes) > 5:
                        prefix_list += f" +{len(vif.route_filter_prefixes) - 5} more"
                    prefixes_html = f'<div class="vif-prefixes"><strong>Prefixes:</strong> {prefix_list}</div>'
                
                vif_cards.append(f'''
                <div class="vif-card {bgp_class}">
                    <div class="vif-header">
                        <div class="vif-title">
                            <span class="vif-status-icon">{vif_state_icon}</span>
                            <span class="vif-name">{html.escape(vif.name)}</span>
                            <span class="vif-type-badge {vif_type_class}">{vif_type_label}</span>
                            <span class="vif-bgp-summary">{bgp_icon} {vif.bgp_summary}</span>
                        </div>
                        <div class="vif-badges">
                            {dxgw_info}
                        </div>
                    </div>
                    <div class="vif-body">
                        <div class="vif-info-grid">
                            <div class="vif-info-item"><span class="label">VIF ID:</span> <code>{vif.id}</code></div>
                            <div class="vif-info-item"><span class="label">VLAN:</span> <code>{vif.vlan}</code></div>
                            <div class="vif-info-item"><span class="label">Customer ASN:</span> <code>{vif.customer_asn}</code></div>
                            <div class="vif-info-item"><span class="label">Amazon ASN:</span> <code>{vif.amazon_asn}</code></div>
                            <div class="vif-info-item"><span class="label">MTU:</span> {vif.mtu} {"(Jumbo)" if vif.jumbo_capable else ""}</div>
                            <div class="vif-info-item"><span class="label">State:</span> <span class="state-badge {vif_state_class}">{vif.state}</span></div>
                        </div>
                        {prefixes_html}
                        {bgp_table}
                    </div>
                </div>''')
            
            cards.append(f'''
            <div class="dx-conn-card {state_class}">
                <div class="dx-conn-header">
                    <div class="dx-conn-title">
                        <span class="dx-conn-icon">{state_icon}</span>
                        <h3>{html.escape(conn_name)}</h3>
                        <span class="dx-conn-bandwidth">{conn_bandwidth}</span>
                    </div>
                    <div class="dx-conn-meta">
                        <span class="dx-location">📍 {html.escape(conn_location)}</span>
                        <span class="dx-provider">🏢 {html.escape(conn_provider)}</span>
                        <span class="dx-redundancy">{conn_redundancy}</span>
                    </div>
                </div>
                <div class="dx-conn-info">
                    <span><strong>Connection ID:</strong> <code>{conn_id}</code></span>
                    <span><strong>State:</strong> <span class="state-badge {state_class}">{conn_state}</span></span>
                </div>
                <div class="dx-conn-body">
                    <div class="vif-section-title">Virtual Interfaces ({len(vifs)})</div>
                    {"".join(vif_cards)}
                </div>
            </div>''')
        
        return "".join(cards)
    
    def _generate_vpc_details_html(self) -> str:
        """Generate VPC details with subnets organized by route table."""
        if not self.data.vpcs:
            return "<p>No local VPCs found. Cross-account VPCs are visible in TGW Attachments tab.</p>"
        
        # Subnet type legend
        legend = '''
        <div class="subnet-legend">
            <span class="legend-title">Subnet Types:</span>
            <span class="subnet-type-badge public">PUBLIC</span> <span class="legend-desc">Route to IGW (internet-facing)</span>
            <span class="subnet-type-badge private">PRIVATE</span> <span class="legend-desc">Route to NAT (outbound only)</span>
            <span class="subnet-type-badge tgw">TGW</span> <span class="legend-desc">Route to Transit Gateway</span>
            <span class="subnet-type-badge isolated">ISOLATED</span> <span class="legend-desc">No internet route</span>
        </div>
        '''
        
        html_parts = [legend]
        
        for vpc in self.data.vpcs.values():
            vpc_name = vpc.name if vpc.name else vpc.id
            vpc_cidrs = ", ".join(vpc.cidrs) if vpc.cidrs else "No CIDR"
            
            # Get all subnets for this VPC
            vpc_subnets = [s for s in self.data.subnets.values() if s.vpc_id == vpc.id]
            
            # Get all route tables for this VPC
            vpc_rts = {rt.id: rt for rt in self.data.vpc_route_tables.values() if rt.vpc_id == vpc.id}
            
            # Group subnets by route table
            subnets_by_rt = defaultdict(list)
            
            for subnet in vpc_subnets:
                rt_id = subnet.route_table_id or vpc.main_route_table_id
                if rt_id:
                    subnets_by_rt[rt_id].append(subnet)
                else:
                    subnets_by_rt["_implicit_"].append(subnet)
            
            # Add route tables that have no subnets associated
            for rt_id in vpc_rts:
                if rt_id not in subnets_by_rt:
                    subnets_by_rt[rt_id] = []
            
            # Build route table sections
            rt_sections = []
            
            # Sort: main RT first, then by name
            sorted_rt_ids = sorted(
                subnets_by_rt.keys(),
                key=lambda x: (
                    x == "_implicit_",  # implicit last
                    not (vpc_rts.get(x, None) and vpc_rts[x].is_main),  # main first
                    vpc_rts.get(x, None) and vpc_rts[x].name or x  # then by name
                )
            )
            
            for rt_id in sorted_rt_ids:
                subnets = subnets_by_rt[rt_id]
                if rt_id == "_implicit_":
                    rt_name = "Implicit (Main RT)"
                    rt_display_id = ""
                    is_main = True
                    default_route_info = ""
                else:
                    rt = vpc_rts.get(rt_id)
                    rt_name = (rt.name if rt and rt.name else rt_id)
                    rt_display_id = rt_id
                    is_main = rt.is_main if rt else False
                    
                    # Determine default route
                    default_route_info = ""
                    if rt:
                        for route in rt.routes:
                            if route.destination == "0.0.0.0/0":
                                if route.target_type == RouteTargetType.IGW:
                                    default_route_info = '<span class="default-route igw">0.0.0.0/0 → IGW</span>'
                                elif route.target_type == RouteTargetType.NAT:
                                    default_route_info = '<span class="default-route nat">0.0.0.0/0 → NAT</span>'
                                elif route.target_type == RouteTargetType.TGW:
                                    default_route_info = '<span class="default-route tgw">0.0.0.0/0 → TGW</span>'
                                else:
                                    default_route_info = f'<span class="default-route other">0.0.0.0/0 → {route.target_type.value}</span>'
                                break
                
                main_badge = ' <span class="badge-main">MAIN</span>' if is_main else ''
                
                # Build subnet rows
                subnet_rows = []
                for subnet in sorted(subnets, key=lambda s: (s.az, s.cidr)):
                    subnet_name = subnet.name if subnet.name else "-"
                    
                    # Type with color
                    type_class = subnet.subnet_type.value
                    type_label = subnet.subnet_type.value.upper()
                    
                    subnet_rows.append(f'''
                    <tr class="subnet-row {type_class}">
                        <td class="subnet-type-cell"><span class="subnet-type-badge {type_class}">{type_label}</span></td>
                        <td class="subnet-name-cell">{html.escape(subnet_name)}</td>
                        <td class="subnet-cidr-cell"><code>{subnet.cidr}</code></td>
                        <td class="subnet-az-cell">{subnet.az}</td>
                        <td class="subnet-id-cell"><code>{subnet.id}</code></td>
                    </tr>''')
                
                # Build routes table
                routes_html = ""
                rt = vpc_rts.get(rt_id) if rt_id != "_implicit_" else None
                if rt and rt.routes:
                    route_rows = []
                    for route in rt.routes:
                        dest = route.destination
                        # Resolve prefix list
                        if dest.startswith("pl-") and dest in self.data.prefix_lists:
                            dest = f"{dest} ({self.data.prefix_lists[dest]})"
                        
                        target_type = route.target_type.value.upper()
                        target_id = route.target_id if route.target_id else "-"
                        
                        # Color code by target type
                        target_class = ""
                        if route.target_type == RouteTargetType.IGW:
                            target_class = "route-igw"
                        elif route.target_type == RouteTargetType.NAT:
                            target_class = "route-nat"
                        elif route.target_type == RouteTargetType.TGW:
                            target_class = "route-tgw"
                        elif route.target_type == RouteTargetType.LOCAL:
                            target_class = "route-local"
                        
                        route_rows.append(f'''
                        <tr class="{target_class}">
                            <td><code>{dest}</code></td>
                            <td>{target_type}</td>
                            <td><code>{target_id}</code></td>
                        </tr>''')
                    
                    routes_html = f'''
                    <div class="routes-section">
                        <div class="routes-title">Routes ({len(rt.routes)})</div>
                        <table class="routes-table">
                            <thead>
                                <tr>
                                    <th>Destination</th>
                                    <th style="width:80px;">Target</th>
                                    <th>Target ID</th>
                                </tr>
                            </thead>
                            <tbody>{"".join(route_rows)}</tbody>
                        </table>
                    </div>'''
                
                # Handle empty subnets
                if subnet_rows:
                    subnets_html = f'''
                        <div class="subnets-section">
                            <div class="subnets-title">Subnets ({len(subnets)})</div>
                            <table class="subnet-table">
                                <thead>
                                    <tr>
                                        <th style="width:80px;">Type</th>
                                        <th>Name</th>
                                        <th style="width:130px;">CIDR</th>
                                        <th style="width:100px;">AZ</th>
                                        <th>Subnet ID</th>
                                    </tr>
                                </thead>
                                <tbody>{"".join(subnet_rows)}</tbody>
                            </table>
                        </div>'''
                else:
                    subnets_html = '''
                        <div class="subnets-section">
                            <div class="subnets-title">Subnets (0)</div>
                            <div style="padding: 1rem; color: #94a3b8; font-size: 0.85rem; text-align: center;">
                                No subnets associated
                            </div>
                        </div>'''
                
                rt_sections.append(f'''
                <div class="rt-section">
                    <div class="rt-section-header">
                        <div class="rt-section-title">
                            <span class="rt-icon">📋</span>
                            <span class="rt-name">{html.escape(rt_name)}</span>
                            {main_badge}
                            {default_route_info}
                        </div>
                        <div class="rt-section-meta">
                            <code>{rt_display_id}</code>
                            <span class="subnet-count">{len(subnets)} subnet{"s" if len(subnets) != 1 else ""}</span>
                        </div>
                    </div>
                    <div class="rt-section-body">
                        {subnets_html}
                        {routes_html}
                    </div>
                </div>''')
            
            # VPC summary badges
            badges = []
            if vpc.igw_id:
                badges.append('<span class="vpc-badge igw">🌐 IGW</span>')
            if vpc.nat_gateway_ids:
                badges.append(f'<span class="vpc-badge nat">🔒 {len(vpc.nat_gateway_ids)} NAT</span>')
            if vpc.tgw_attachment_id:
                badges.append('<span class="vpc-badge tgw">🔗 TGW</span>')
            
            html_parts.append(f'''
            <div class="vpc-details-card">
                <div class="vpc-details-header">
                    <div class="vpc-details-title">
                        <h3>{html.escape(vpc_name)}</h3>
                        <code class="vpc-id">{vpc.id}</code>
                    </div>
                    <div class="vpc-details-badges">
                        <span class="vpc-cidr-badge">{vpc_cidrs}</span>
                        {"".join(badges)}
                    </div>
                </div>
                <div class="vpc-details-stats">
                    <span>📊 {len(vpc_subnets)} Subnets</span>
                    <span>📋 {len(vpc_rts)} Route Tables</span>
                </div>
                <div class="vpc-details-body">
                    {"".join(rt_sections) if rt_sections else "<p>No subnets found</p>"}
                </div>
            </div>''')
        
        return "".join(html_parts)
    
    def _generate_vpc_tables_html(self) -> str:
        html_parts = []
        
        for vpc in self.data.vpcs.values():
            vpc_rts = [rt for rt in self.data.vpc_route_tables.values() if rt.vpc_id == vpc.id]
            
            for rt in vpc_rts:
                badges = []
                if rt.is_main:
                    badges.append('<span class="badge">Main</span>')
                
                # Handle empty subnet names
                subnet_names = []
                for s in rt.subnet_ids:
                    if s in self.data.subnets:
                        subnet = self.data.subnets[s]
                        subnet_names.append(subnet.name if subnet.name else s)
                
                # Handle empty VPC and RT names
                vpc_display = vpc.name if vpc.name else vpc.id
                rt_display = rt.name if rt.name else rt.id
                
                meta = [f"<strong>VPC:</strong> {vpc_display}", f"<strong>ID:</strong> {rt.id}"]
                if subnet_names:
                    meta.append(f"<strong>Subnets:</strong> {', '.join(subnet_names[:5])}")
                
                rows = ""
                for route in rt.routes:
                    target = route.target_id if route.target_id else "-"
                    target_type = route.target_type.value
                    
                    # Resolve prefix list
                    dest = route.destination
                    if dest.startswith("pl-") and dest in self.data.prefix_lists:
                        dest = f"{dest} ({self.data.prefix_lists[dest]})"
                    
                    rows += f'''
                    <tr>
                        <td>{dest}</td>
                        <td>{target_type}</td>
                        <td>{target}</td>
                    </tr>'''
                
                html_parts.append(f'''
                <div class="route-table-card">
                    <div class="route-table-header">
                        <span>{html.escape(rt_display)}</span>
                        <span>{" ".join(badges)}</span>
                    </div>
                    <div class="route-table-meta">{" &nbsp;|&nbsp; ".join(meta)}</div>
                    <table>
                        <thead>
                            <tr>
                                <th>Destination</th>
                                <th>Target Type</th>
                                <th>Target</th>
                            </tr>
                        </thead>
                        <tbody>{rows}</tbody>
                    </table>
                </div>''')
        
        return "".join(html_parts) if html_parts else "<p>No VPC route tables found.</p>"
    
    def _generate_issues_html(self, issues: list) -> str:
        if not issues:
            return '<p style="color: #28a745;">✓ No issues detected</p>'
        
        items = []
        for issue in issues:
            severity = issue.get("severity", "info")
            issue_type = issue.get("type", "")
            
            # Choose icon based on issue type
            if issue_type == "blackhole":
                icon = "🕳️"
            elif issue_type == "asymmetric":
                icon = "↔️"
            elif issue_type == "vpn_down":
                icon = "❌"
                severity = "error"
            elif issue_type == "vpn_partial":
                icon = "⚠️"
            elif issue_type in ["dx_down", "vif_down", "bgp_down"]:
                icon = "❌"
                severity = "error"
            elif issue_type in ["dx_degraded", "bgp_partial"]:
                icon = "⚠️"
            elif issue_type == "overlap":
                icon = "⚠️"
            elif severity == "error":
                icon = "❌"
            elif severity == "warning":
                icon = "⚠️"
            else:
                icon = "ℹ️"
            
            items.append(f'''
            <div class="issue-item {severity}">
                <span class="issue-icon">{icon}</span>
                <div class="issue-content">
                    <div class="issue-type">{issue["type"].upper().replace("_", " ")}</div>
                    <div class="issue-message">{issue["message"]}</div>
                    <div class="issue-location">Location: {issue["location"]}</div>
                </div>
            </div>''')
        
        return "".join(items)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="AWS Network Diagram Tool v3.3")
    parser.add_argument("-i", "--input-dir", type=Path, default=Path("./aws-data"),
                       help="Directory containing AWS CLI JSON output")
    parser.add_argument("-o", "--output", type=Path, default=Path("network-report.html"),
                       help="Output HTML report file")
    parser.add_argument("--mermaid", type=Path, help="Also export Mermaid diagram to file")
    parser.add_argument("--json", type=Path, help="Export raw data as JSON")
    
    args = parser.parse_args()
    
    print(f"Loading AWS data from {args.input_dir}...")
    loader = AWSDataLoader(args.input_dir)
    data = loader.load()
    
    cross_account = data.cross_account_attachments
    local = data.local_attachments
    
    # Show account mode
    if data.is_hub_account:
        print(f"\n🏠 Hub Account Mode (TGW owner: {data.local_account_id})")
    elif data.is_spoke_account:
        tgw_ids = ", ".join(sorted(data.referenced_tgw_ids))
        print(f"\n📍 Spoke Account Mode ({data.local_account_id})")
        print(f"   TGW route tables not visible - run from hub account for full visibility")
        print(f"   Referenced TGW: {tgw_ids}")
    
    print(f"\nFound:")
    print(f"  • {len(data.tgws)} Transit Gateway(s)")
    print(f"  • {len(data.tgw_attachments)} TGW Attachment(s)")
    if cross_account:
        print(f"    └─ {len(cross_account)} cross-account (from spoke accounts)")
        print(f"    └─ {len(local)} local")
    print(f"  • {len(data.tgw_route_tables)} TGW Route Table(s)")
    print(f"  • {len(data.vpcs)} Local VPC(s)")
    
    # Show VPN connections
    if data.vpn_connections:
        tunnels_up = sum(1 for v in data.vpn_connections.values() for t in v.tunnels if t.status == "UP")
        tunnels_total = sum(len(v.tunnels) for v in data.vpn_connections.values())
        print(f"  • {len(data.vpn_connections)} VPN Connection(s) ({tunnels_up}/{tunnels_total} tunnels UP)")
    
    # Show DX stats
    if data.dx_vifs:
        bgp_up = sum(1 for v in data.dx_vifs.values() for p in v.bgp_peers if p.bgp_status.lower() == "up")
        bgp_total = sum(len(v.bgp_peers) for v in data.dx_vifs.values())
        print(f"  • {len(data.dx_vifs)} DX VIF(s) ({bgp_up}/{bgp_total} BGP UP)")
    
    # Show cross-account VPCs with extracted CIDRs
    if cross_account:
        print(f"\n📡 Cross-Account Attachments (CIDRs from propagated routes):")
        for att in cross_account:
            cidrs = ", ".join(att.cidrs) if att.cidrs else "no CIDRs propagated"
            print(f"   • {att.name} ({att.resource_owner_id}) - {cidrs}")
    
    # Show VPN details
    if data.vpn_connections:
        print(f"\n🔐 VPN Connections:")
        for vpn in data.vpn_connections.values():
            up = sum(1 for t in vpn.tunnels if t.status == "UP")
            total = len(vpn.tunnels)
            status_icon = "✅" if up == total else ("⚠️" if up > 0 else "❌")
            cgw = data.customer_gateways.get(vpn.customer_gateway_id)
            cgw_ip = cgw.ip_address if cgw else "?"
            print(f"   {status_icon} {vpn.name}: {up}/{total} tunnels UP (CGW: {cgw_ip})")
    
    # Show DX details
    if data.dx_vifs:
        print(f"\n🔌 Direct Connect VIFs:")
        for vif in data.dx_vifs.values():
            up = sum(1 for p in vif.bgp_peers if p.bgp_status.lower() == "up")
            total = len(vif.bgp_peers)
            status_icon = "✅" if up == total else ("⚠️" if up > 0 else "❌")
            conn = data.dx_connections.get(vif.connection_id)
            location = conn.location if conn else "?"
            print(f"   {status_icon} {vif.name}: {vif.vif_type} ({up}/{total} BGP UP) @ {location}")
    
    # Generate HTML report
    print(f"\nGenerating HTML report...")
    generator = HTMLReportGenerator(data)
    html_content = generator.generate()
    
    with open(args.output, "w") as f:
        f.write(html_content)
    print(f"✓ Report saved to {args.output}")
    
    # Export Mermaid if requested
    if args.mermaid:
        mermaid = generator._generate_mermaid()
        with open(args.mermaid, "w") as f:
            f.write(mermaid)
        print(f"✓ Mermaid diagram saved to {args.mermaid}")
    
    # Run analysis
    analyzer = ConnectivityAnalyzer(data)
    issues = analyzer.find_issues()
    
    if issues:
        print(f"\n⚠️  {len(issues)} issue(s) detected:")
        for issue in issues[:5]:
            print(f"   • [{issue['type']}] {issue['message']}")
        if len(issues) > 5:
            print(f"   ... and {len(issues) - 5} more")
    else:
        print("\n✓ No issues detected")


if __name__ == "__main__":
    main()
