#!/bin/bash
#
# AWS Network Data Export Script v3.3
# 
# Exports all AWS networking data needed for the network diagram tool.
# Supports multi-account and multi-region collection.
#
# Usage:
#   ./export_aws_data.sh <output-dir> [region] [profile]
#   ./export_aws_data.sh ./aws-data us-east-1 production
#
# Requirements:
#   - AWS CLI v2 installed and configured
#   - jq installed for JSON processing
#   - Appropriate IAM permissions (see README)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Arguments
OUTPUT_DIR="${1:-./aws-data}"
REGION="${2:-$(aws configure get region 2>/dev/null || echo 'us-east-1')}"
PROFILE="${3:-}"

# Build AWS CLI base command
AWS_CMD="aws"
if [ -n "$PROFILE" ]; then
    AWS_CMD="aws --profile $PROFILE"
fi
AWS_CMD="$AWS_CMD --region $REGION"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         AWS Network Data Export Script v3.3                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Output:  ${GREEN}$OUTPUT_DIR${NC}"
echo -e "  Region:  ${GREEN}$REGION${NC}"
echo -e "  Profile: ${GREEN}${PROFILE:-default}${NC}"
echo ""

# Check dependencies
command -v jq >/dev/null 2>&1 || { echo -e "${RED}Error: jq is required but not installed.${NC}" >&2; exit 1; }
command -v aws >/dev/null 2>&1 || { echo -e "${RED}Error: AWS CLI is required but not installed.${NC}" >&2; exit 1; }

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Helper function to run AWS CLI commands
run_aws() {
    local output_file="$1"
    shift
    local cmd="$@"
    
    echo -n "  Exporting $output_file... "
    
    if $AWS_CMD $cmd > "$OUTPUT_DIR/$output_file" 2>/dev/null; then
        local count=$(jq 'to_entries | .[0].value | if type == "array" then length else 1 end' "$OUTPUT_DIR/$output_file" 2>/dev/null || echo "?")
        echo -e "${GREEN}✓${NC} ($count items)"
        return 0
    else
        echo '{}' > "$OUTPUT_DIR/$output_file"
        echo -e "${YELLOW}⚠${NC} (none/error)"
        return 1
    fi
}

echo -e "${BLUE}[1/6] Transit Gateway Resources${NC}"
echo "────────────────────────────────"
run_aws "transit-gateways.json" ec2 describe-transit-gateways
run_aws "transit-gateway-attachments.json" ec2 describe-transit-gateway-attachments
run_aws "transit-gateway-route-tables.json" ec2 describe-transit-gateway-route-tables

# Export routes, associations, and propagations for each TGW route table
TGW_RTS=$(jq -r '.TransitGatewayRouteTables[]?.TransitGatewayRouteTableId // empty' "$OUTPUT_DIR/transit-gateway-route-tables.json" 2>/dev/null)
for RT_ID in $TGW_RTS; do
    echo -n "  Exporting routes-$RT_ID.json... "
    if $AWS_CMD ec2 search-transit-gateway-routes \
        --transit-gateway-route-table-id "$RT_ID" \
        --filters "Name=state,Values=active,blackhole" \
        > "$OUTPUT_DIR/routes-$RT_ID.json" 2>/dev/null; then
        count=$(jq '.Routes | length' "$OUTPUT_DIR/routes-$RT_ID.json" 2>/dev/null || echo "?")
        echo -e "${GREEN}✓${NC} ($count routes)"
    else
        echo '{"Routes":[]}' > "$OUTPUT_DIR/routes-$RT_ID.json"
        echo -e "${YELLOW}⚠${NC}"
    fi
    
    echo -n "  Exporting associations-$RT_ID.json... "
    if $AWS_CMD ec2 get-transit-gateway-route-table-associations \
        --transit-gateway-route-table-id "$RT_ID" \
        > "$OUTPUT_DIR/associations-$RT_ID.json" 2>/dev/null; then
        count=$(jq '.Associations | length' "$OUTPUT_DIR/associations-$RT_ID.json" 2>/dev/null || echo "?")
        echo -e "${GREEN}✓${NC} ($count)"
    else
        echo '{"Associations":[]}' > "$OUTPUT_DIR/associations-$RT_ID.json"
        echo -e "${YELLOW}⚠${NC}"
    fi
    
    echo -n "  Exporting propagations-$RT_ID.json... "
    if $AWS_CMD ec2 get-transit-gateway-route-table-propagations \
        --transit-gateway-route-table-id "$RT_ID" \
        > "$OUTPUT_DIR/propagations-$RT_ID.json" 2>/dev/null; then
        count=$(jq '.TransitGatewayRouteTablePropagations | length' "$OUTPUT_DIR/propagations-$RT_ID.json" 2>/dev/null || echo "?")
        echo -e "${GREEN}✓${NC} ($count)"
    else
        echo '{"TransitGatewayRouteTablePropagations":[]}' > "$OUTPUT_DIR/propagations-$RT_ID.json"
        echo -e "${YELLOW}⚠${NC}"
    fi
done
echo ""

echo -e "${BLUE}[2/6] VPC Resources${NC}"
echo "───────────────────"
run_aws "vpcs.json" ec2 describe-vpcs
run_aws "subnets.json" ec2 describe-subnets
run_aws "vpc-route-tables.json" ec2 describe-route-tables
echo ""

echo -e "${BLUE}[3/6] Gateways${NC}"
echo "──────────────"
run_aws "internet-gateways.json" ec2 describe-internet-gateways
run_aws "nat-gateways.json" ec2 describe-nat-gateways
run_aws "vpn-gateways.json" ec2 describe-vpn-gateways
run_aws "customer-gateways.json" ec2 describe-customer-gateways
run_aws "egress-only-igws.json" ec2 describe-egress-only-internet-gateways
echo ""

echo -e "${BLUE}[4/6] Connections${NC}"
echo "─────────────────"
run_aws "vpc-peering-connections.json" ec2 describe-vpc-peering-connections
run_aws "vpn-connections.json" ec2 describe-vpn-connections
run_aws "vpc-endpoints.json" ec2 describe-vpc-endpoints
echo ""

echo -e "${BLUE}[5/6] Additional Resources${NC}"
echo "──────────────────────────"
run_aws "prefix-lists.json" ec2 describe-managed-prefix-lists
run_aws "network-interfaces.json" ec2 describe-network-interfaces \
    --filters "Name=interface-type,Values=transit_gateway"
run_aws "security-groups.json" ec2 describe-security-groups
echo ""

echo -e "${BLUE}[6/6] Direct Connect (if available)${NC}"
echo "────────────────────────────────────"
run_aws "dx-connections.json" directconnect describe-connections || true
run_aws "dx-gateways.json" directconnect describe-direct-connect-gateways || true
run_aws "dx-gateway-attachments.json" directconnect describe-direct-connect-gateway-attachments || true
run_aws "dx-vifs.json" directconnect describe-virtual-interfaces || true
echo ""

# Create metadata file
echo -e "${BLUE}Creating metadata...${NC}"
cat > "$OUTPUT_DIR/metadata.json" << EOF
{
    "export_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "region": "$REGION",
    "profile": "${PROFILE:-default}",
    "aws_account_id": "$($AWS_CMD sts get-caller-identity --query Account --output text 2>/dev/null || echo 'unknown')",
    "export_version": "3.0"
}
EOF
echo -e "  ${GREEN}✓${NC} metadata.json"
echo ""

# Summary
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                       Export Complete                          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Files exported to: $OUTPUT_DIR"
echo ""
echo "  Next steps:"
echo "    python network_diagram.py -i $OUTPUT_DIR -o network-report.html"
echo ""
