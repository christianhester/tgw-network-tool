# AWS Network Diagram Tool v3.3

A comprehensive tool for visualizing AWS Transit Gateway and VPC network architecture. Generates interactive HTML reports with full route table details.

![Network Diagram](https://img.shields.io/badge/AWS-Network%20Diagram-orange?logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

### Transit Gateway Visualization
- **TGW Route Tables** with ALL AWS console fields:
  - CIDR / Prefix List ID
  - Attachment ID & Target Name
  - Owner Account (for cross-account)
  - Resource Type (VPC, VPN, Direct Connect)
  - Route Type (static/propagated)
  - Route State (active/blackhole)
- **TGW Attachments** with complete details
- **Associations & Propagations** tracking
- **Cross-Account Support** - Detects RAM-shared TGW attachments

### Hybrid Connectivity
- **VPN Connections** with tunnel status monitoring
- **Direct Connect** connections, VIFs, and BGP peers
- Customer Gateway details (IP, ASN, device)
- DX Gateway associations
- BGP session health tracking

### VPC & Subnet Visualization
- **VPCs grouped with their subnets and route tables**
- Subnet classification (public/private/isolated/tgw)
- Route tables with all routes displayed inline
- Internet Gateway and NAT Gateway detection
- VPC Peering connections

### Connectivity Analysis
- Asymmetric routing detection
- Blackhole route identification
- VPN tunnel status alerts
- DX/BGP session monitoring
- CIDR overlap warnings
- Missing route alerts
- Peering status checks

### Output Formats
- **HTML Report** - Interactive dashboard with tabs
- **Mermaid Diagram** - Color-coded network topology
- **JSON Export** - Raw data for further processing

## Quick Start

### 1. Export AWS Data

```bash
# Make the script executable
chmod +x export_aws_data.sh

# Export data from your AWS account
./export_aws_data.sh ./aws-data us-east-1 my-profile
```

### 2. Generate Report

```bash
# Generate HTML report
python network_diagram.py -i ./aws-data -o network-report.html

# Also export Mermaid diagram
python network_diagram.py -i ./aws-data -o network-report.html --mermaid diagram.mmd
```

### 3. View Report

Open `network-report.html` in your browser.

## Required IAM Permissions

The export script requires these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:GetTransitGatewayRouteTableAssociations",
        "ec2:GetTransitGatewayRouteTablePropagations",
        "ec2:SearchTransitGatewayRoutes",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeVpnGateways",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeManagedPrefixLists",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "directconnect:DescribeConnections",
        "directconnect:DescribeDirectConnectGateways",
        "directconnect:DescribeDirectConnectGatewayAttachments",
        "directconnect:DescribeVirtualInterfaces"
      ],
      "Resource": "*"
    }
  ]
}
```

## Report Sections

### Diagram View
Visual representation of your network showing:
- Transit Gateway as central hub (orange)
- TGW Route Tables with routes (dark boxes)
- VPC attachments with CIDRs (blue = local, orange = cross-account)
- VPN connections (green)
- Direct Connect connections (purple)
- Color-coded connection lines matching node colors

### TGW Route Tables Tab
Full AWS console-style route table display:

| State | CIDR / Prefix List | Attachment ID | Target Name | Owner Account | Resource Type | Route Type |
|-------|-------------------|---------------|-------------|---------------|---------------|------------|
| active | 10.1.0.0/16 | tgw-attach-0prod... | Production-VPC | 🔗 444455556666 | vpc | propagated |
| active | 0.0.0.0/0 | tgw-attach-0shared... | Shared-Services | ...3333 | vpc | static |
| blackhole | 10.1.0.0/16 | - | - | - | - | static |

### TGW Attachments Tab
Card view of all attachments showing:
- **CROSS-ACCOUNT** badge for RAM-shared attachments
- Attachment ID & Resource ID
- Owner Account
- CIDRs (extracted from propagated routes for cross-account)
- Associated Route Table
- Propagates To list

### VPCs & Subnets Tab
Complete VPC details organized by route table:
- VPC header with CIDR, IGW/NAT/TGW badges
- Each route table section shows:
  - Route table name with MAIN badge
  - Default route indicator (0.0.0.0/0 → IGW/NAT/TGW)
  - **Subnets table**: Type, Name, CIDR, AZ, Subnet ID
  - **Routes table**: Destination, Target Type, Target ID

### VPN Connections Tab
Site-to-Site VPN monitoring with:
- **Status indicators**: ✅ All UP, ⚠️ Partial, ❌ All DOWN
- **Tunnel details**: Outside IP, status, accepted route count
- **Customer Gateway info**: IP address, BGP ASN, device type
- **Connection features**: Acceleration enabled, BGP/Static routing
- Color-coded cards (green/amber/red based on tunnel health)

### Direct Connect Tab
Direct Connect monitoring with:
- **DX Gateways**: Name, ASN, state, account
- **Connections**: Location, bandwidth, provider, redundancy status
- **Virtual Interfaces (VIFs)**: 
  - Type (Transit/Private/Public)
  - VLAN, MTU, ASN info
  - BGP peer status with addresses
  - Route filter prefixes (for public VIFs)
- Color-coded by BGP health (green/amber/red)

### Issues Tab
Detected network issues:
- 🕳️ **BLACKHOLE** - Routes dropping traffic
- ↔️ **ASYMMETRIC** - One-way connectivity
- ❌ **VPN DOWN** - All tunnels down
- ⚠️ **VPN PARTIAL** - Some tunnels down
- ❌ **DX DOWN** - Connection down
- ❌ **BGP DOWN** - All BGP peers down  
- ⚠️ **BGP PARTIAL** - Some BGP peers down
- ⚠️ **OVERLAP** - CIDR conflicts
- ℹ️ **MISSING** - Incomplete routing

## File Structure

```
tgw-network-tool/
├── network_diagram.py      # Main tool
├── export_aws_data.sh      # AWS data export script
├── README.md               # This file
└── sample-data/            # Example AWS data
    ├── transit-gateways.json
    ├── transit-gateway-attachments.json
    ├── transit-gateway-route-tables.json
    ├── routes-*.json
    ├── associations-*.json
    ├── propagations-*.json
    ├── vpcs.json
    ├── subnets.json
    ├── vpc-route-tables.json
    └── ...
```

## Command Line Options

```
usage: network_diagram.py [-h] [-i INPUT_DIR] [-o OUTPUT] [--mermaid MERMAID] [--json JSON]

AWS Network Diagram Tool v3.3

options:
  -h, --help            show this help message and exit
  -i INPUT_DIR, --input-dir INPUT_DIR
                        Directory containing AWS CLI JSON output (default: ./aws-data)
  -o OUTPUT, --output OUTPUT
                        Output HTML report file (default: network-report.html)
  --mermaid MERMAID     Also export Mermaid diagram to file
  --json JSON           Export raw data as JSON
```

## Cross-Account / RAM-Shared TGW Support

The tool supports both centralized (hub) and distributed (spoke) deployment patterns.

### Hub Account (TGW Owner)

**Run from the network account that owns the TGW for full visibility.**

```bash
./export_aws_data.sh ./hub-data us-east-1 network-account-profile
python network_diagram.py -i ./hub-data -o hub-report.html
```

The tool will show:
- ✅ All TGW route tables and routes
- ✅ All attachments (including from spoke accounts)
- ✅ Spoke VPC CIDRs extracted from propagated routes
- ✅ Owner account ID for each attachment
- ✅ Cross-account VPCs with orange color and 🔗 badge
- ✅ Full connectivity analysis

Console output shows: `🏠 Hub Account Mode (TGW owner: 111122223333)`

### Spoke Account (RAM Shared)

**You can also run from spoke accounts for local visibility.**

```bash
./export_aws_data.sh ./spoke-data us-east-1 spoke-account-profile
python network_diagram.py -i ./spoke-data -o spoke-report.html
```

The tool will show:
- ✅ Your local VPCs, subnets, and route tables
- ✅ Your TGW attachments with connection status
- ✅ Referenced TGW ID (even though you can't see its details)
- ✅ Spoke-focused diagram centered on your VPCs
- ⚠️ Guidance banner noting limited TGW visibility

Console output shows:
```
📍 Spoke Account Mode (444455556666)
   TGW route tables not visible - run from hub account for full visibility
   Referenced TGW: tgw-0hub123456789abcd
```

### What Each Account Can See

| Resource | Hub Account | Spoke Account |
|----------|-------------|---------------|
| TGW details | ✅ Full | ❌ Not visible |
| TGW route tables | ✅ All routes | ❌ Not visible |
| TGW attachments | ✅ All accounts | ✅ Own only |
| Local VPCs | ✅ Full | ✅ Full |
| Local subnets | ✅ Full | ✅ Full |
| Local route tables | ✅ Full | ✅ Full |
| VPN/DX | ✅ Own | ✅ Own |

### Recommended Workflow

For complete network visibility:
1. **Primary report**: Run from hub/network account
2. **Supplemental reports**: Run from spoke accounts for local VPC details

This gives you centralized TGW routing visibility plus detailed subnet-level information from each account.

## Multi-Region Support

For multi-region environments:

```bash
# Export from each region
./export_aws_data.sh ./us-east-1-data us-east-1 my-profile
./export_aws_data.sh ./us-west-2-data us-west-2 my-profile

# Generate separate reports
python network_diagram.py -i ./us-east-1-data -o us-east-1-report.html
python network_diagram.py -i ./us-west-2-data -o us-west-2-report.html
```

## Architecture Patterns Detected

The tool recognizes common AWS networking patterns:

### Hub-and-Spoke
- Shared Services VPC as hub
- Spoke VPCs for workloads
- Centralized egress through NAT/IGW

### Isolated Environments
- Blackhole routes for prod/dev isolation
- Separate route tables per environment

### Inspection VPC
- Security/firewall VPC in traffic path
- Default routes through inspection

### Hybrid Connectivity
- VPN/Direct Connect to on-premises
- Route propagation from BGP

## Troubleshooting

### "No Transit Gateways found"
- Check IAM permissions
- Verify region is correct
- Ensure TGW exists in the account

### Routes missing from tables
- The tool uses `search-transit-gateway-routes` with state filter
- Only active and blackhole routes are exported
- Check if routes exist in AWS console

### Diagram too large
- For large environments, the Mermaid diagram may be hard to read
- Use the HTML tabs for detailed route tables
- Consider filtering to specific TGWs

## Contributing

Contributions welcome! Please:
1. Fork the repo
2. Create a feature branch
3. Submit a PR

## License

MIT License - See LICENSE file
