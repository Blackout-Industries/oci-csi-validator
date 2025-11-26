#!/usr/bin/env python3
import os
import sys
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional
from pathlib import Path

import click
from dotenv import load_dotenv
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
console = Console()


def truncate_id(id_string: str, start_chars: int = 8, end_chars: int = 8) -> str:
    if len(id_string) <= (start_chars + end_chars + 3):
        return id_string
    return f"{id_string[:start_chars]}...{id_string[-end_chars:]}"


def group_attachments_by_node(attachments: List) -> Dict[str, List]:
    grouped = defaultdict(list)
    for att in attachments:
        grouped[att.node_name].append(att)
    return dict(grouped)


@dataclass
class VolumeAttachmentInfo:

    name: str
    node_name: str
    pv_name: str
    age_seconds: float
    attacher: str
    is_orphaned: bool

    @property
    def age_human(self) -> str:

        hours = int(self.age_seconds // 3600)
        minutes = int((self.age_seconds % 3600) // 60)
        if hours > 0:
            return f"{hours}h{minutes}m"
        return f"{minutes}m"

    def to_dict(self) -> Dict:

        data = asdict(self)
        data['age_human'] = self.age_human
        return data


@dataclass
class ValidationReport:

    total_attachments: int
    active_nodes: int
    orphaned_attachments: List[VolumeAttachmentInfo]
    healthy_attachments: int
    compartment_id: str
    k8s_context: str
    scan_timestamp: str

    def to_dict(self) -> Dict:

        return {
            'total_attachments': self.total_attachments,
            'active_nodes': self.active_nodes,
            'orphaned_count': len(self.orphaned_attachments),
            'healthy_count': self.healthy_attachments,
            'compartment_id': self.compartment_id,
            'k8s_context': self.k8s_context,
            'scan_timestamp': self.scan_timestamp,
            'orphaned_attachments': [att.to_dict() for att in self.orphaned_attachments]
        }


class ConfigValidator:


    @staticmethod
    def load_config() -> Dict[str, str]:

        # Load .env file if it exists
        env_path = Path('.env')
        if env_path.exists():
            load_dotenv(env_path)
            logger.info(f"Loaded configuration from {env_path.absolute()}")
        else:
            logger.warning(".env file not found, using environment variables")

        config_dict = {
            'compartment_id': os.getenv('OCI_COMPARTMENT_ID', ''),
            'k8s_context': os.getenv('K8S_CONTEXT', ''),
            'oci_config_file': os.getenv('OCI_CONFIG_FILE', str(Path.home() / '.oci' / 'config')),
            'oci_config_profile': os.getenv('OCI_CONFIG_PROFILE', 'DEFAULT')
        }

        # Validate required fields
        if not config_dict['compartment_id']:
            raise ValueError(
                "OCI_COMPARTMENT_ID is required. Set it in .env file or environment variable."
            )

        return config_dict


class KubernetesClient:


    def __init__(self, context: Optional[str] = None):

        try:
            if context:
                config.load_kube_config(context=context)
                logger.info(f"Connected to Kubernetes context: {context}")
            else:
                config.load_kube_config()
                current_context = config.list_kube_config_contexts()[1]['name']
                logger.info(f"Connected to current Kubernetes context: {current_context}")

            self.storage_v1 = client.StorageV1Api()
            self.core_v1 = client.CoreV1Api()
            self.context = context or current_context

        except Exception as e:
            logger.error(f"Failed to connect to Kubernetes: {e}")
            raise

    def get_active_nodes(self) -> set:

        try:
            nodes = self.core_v1.list_node()
            node_names = {node.metadata.name for node in nodes.items}
            logger.info(f"Found {len(node_names)} active nodes")
            return node_names
        except ApiException as e:
            logger.error(f"Failed to list nodes: {e}")
            raise

    def get_volume_attachments(self) -> List[VolumeAttachmentInfo]:

        try:
            attachments = self.storage_v1.list_volume_attachment()
            logger.info(f"Found {len(attachments.items)} VolumeAttachments")

            attachment_list = []
            now = datetime.now(timezone.utc)

            for att in attachments.items:
                # Calculate age
                created = att.metadata.creation_timestamp
                age_seconds = (now - created).total_seconds()

                # Extract metadata
                node_name = att.spec.node_name
                pv_name = att.spec.source.persistent_volume_name or "N/A"
                attacher = att.spec.attacher

                attachment_list.append(VolumeAttachmentInfo(
                    name=att.metadata.name,
                    node_name=node_name,
                    pv_name=pv_name,
                    age_seconds=age_seconds,
                    attacher=attacher,
                    is_orphaned=False  # Will be set by validator
                ))

            return attachment_list

        except ApiException as e:
            logger.error(f"Failed to list VolumeAttachments: {e}")
            raise

    def delete_volume_attachment(self, name: str) -> bool:

        try:
            self.storage_v1.delete_volume_attachment(name=name)
            logger.info(f"Deleted VolumeAttachment: {name}")
            return True
        except ApiException as e:
            logger.error(f"Failed to delete VolumeAttachment {name}: {e}")
            return False


class VolumeAttachmentValidator:


    def __init__(self, k8s_client: KubernetesClient, compartment_id: str):

        self.k8s_client = k8s_client
        self.compartment_id = compartment_id

    def validate(self) -> ValidationReport:

        logger.info("Starting validation scan...")

        # Get current state
        active_nodes = self.k8s_client.get_active_nodes()
        attachments = self.k8s_client.get_volume_attachments()

        # Identify orphaned attachments
        orphaned = []
        for att in attachments:
            if att.node_name not in active_nodes:
                att.is_orphaned = True
                orphaned.append(att)
                logger.warning(
                    f"Orphaned: {att.name} -> Node: {att.node_name} (age: {att.age_human})"
                )

        report = ValidationReport(
            total_attachments=len(attachments),
            active_nodes=len(active_nodes),
            orphaned_attachments=orphaned,
            healthy_attachments=len(attachments) - len(orphaned),
            compartment_id=self.compartment_id,
            k8s_context=self.k8s_client.context,
            scan_timestamp=datetime.now(timezone.utc).isoformat()
        )

        logger.info(f"Scan complete: {len(orphaned)} orphaned, {report.healthy_attachments} healthy")
        return report

    def cleanup_orphaned(
        self,
        orphaned: List[VolumeAttachmentInfo],
        skip_confirmation: bool = False
    ) -> Dict[str, int]:

        if not orphaned:
            logger.info("No orphaned attachments to clean up")
            return {'deleted': 0, 'failed': 0, 'skipped': 0}

        # Confirmation prompt for large batches
        if len(orphaned) > 5 and not skip_confirmation:
            click.echo(
                f"\n⚠️  You are about to delete {len(orphaned)} VolumeAttachments.",
                err=True
            )
            if not click.confirm("Do you want to continue?"):
                logger.info("Cleanup cancelled by user")
                return {'deleted': 0, 'failed': 0, 'skipped': len(orphaned)}

        # Re-validate nodes immediately before deletion
        logger.info("Re-validating node list before deletion...")
        active_nodes = self.k8s_client.get_active_nodes()

        results = {'deleted': 0, 'failed': 0, 'skipped': 0}

        for att in orphaned:
            # Double-check node doesn't exist
            if att.node_name in active_nodes:
                logger.warning(
                    f"Skipping {att.name}: node {att.node_name} now exists"
                )
                results['skipped'] += 1
                continue

            # Attempt deletion
            if self.k8s_client.delete_volume_attachment(att.name):
                results['deleted'] += 1
            else:
                results['failed'] += 1

        logger.info(
            f"Cleanup complete: {results['deleted']} deleted, "
            f"{results['failed']} failed, {results['skipped']} skipped"
        )
        return results


def print_human_report(report: ValidationReport) -> None:

    console.print()

    # Header panel
    header = Panel(
        Text("OCI CSI VolumeAttachment Validator", style="bold cyan", justify="center"),
        box=box.DOUBLE,
        border_style="cyan"
    )
    console.print(header)

    # Summary stats
    console.print()
    summary_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value")

    summary_table.add_row("Compartment", truncate_id(report.compartment_id, 12, 12))
    summary_table.add_row("Kubernetes Context", f"[cyan]{report.k8s_context}[/cyan]")
    summary_table.add_row("Scan Time", report.scan_timestamp.split('T')[0] + " " + report.scan_timestamp.split('T')[1][:8])
    summary_table.add_row("", "")
    summary_table.add_row("Total VolumeAttachments", f"[blue]{report.total_attachments}[/blue]")
    summary_table.add_row("Active Nodes", f"[green]{report.active_nodes}[/green]")
    summary_table.add_row("Healthy Attachments", f"[green]{report.healthy_attachments}[/green]")

    if report.orphaned_attachments:
        summary_table.add_row("Orphaned Attachments", f"[red bold]{len(report.orphaned_attachments)}[/red bold] ⚠️")
    else:
        summary_table.add_row("Orphaned Attachments", "[green]0[/green] ✅")

    console.print(summary_table)
    console.print()

    if report.orphaned_attachments:
        # Group attachments by node
        grouped = group_attachments_by_node(report.orphaned_attachments)

        console.print(Panel(
            f"[yellow bold]⚠️  Found {len(report.orphaned_attachments)} orphaned attachments across {len(grouped)} missing nodes[/yellow bold]",
            box=box.ROUNDED,
            border_style="yellow"
        ))
        console.print()

        # Display grouped by node
        for node_name, attachments in grouped.items():
            node_panel = Panel(
                f"[red bold]Missing Node:[/red bold] {node_name} [dim]({len(attachments)} orphaned attachments)[/dim]",
                box=box.ROUNDED,
                border_style="red"
            )
            console.print(node_panel)

            # Create table for attachments on this node
            att_table = Table(box=box.SIMPLE_HEAD, show_lines=False)
            att_table.add_column("Attachment ID", style="cyan", no_wrap=True)
            att_table.add_column("Volume ID", style="blue", no_wrap=True)
            att_table.add_column("Age", style="yellow", justify="right")
            att_table.add_column("Attacher", style="dim")

            for att in sorted(attachments, key=lambda x: x.age_seconds, reverse=True):
                att_table.add_row(
                    truncate_id(att.name, 12, 12),
                    truncate_id(att.pv_name, 12, 12),
                    att.age_human,
                    att.attacher.split('.')[-2] if '.' in att.attacher else att.attacher
                )

            console.print(att_table)
            console.print()

        # Footer hint
        console.print(Panel(
            "[bold cyan]💡 Tip:[/bold cyan] Run with [bold]--delete[/bold] flag to clean up orphaned attachments",
            box=box.ROUNDED,
            border_style="cyan"
        ))
    else:
        console.print(Panel(
            "[green bold]✅ No orphaned attachments found - All volume attachments are healthy![/green bold]",
            box=box.ROUNDED,
            border_style="green"
        ))

    console.print()


def print_json_report(report: ValidationReport) -> None:

    click.echo(json.dumps(report.to_dict(), indent=2))


@click.command()
@click.option(
    '--delete',
    is_flag=True,
    help='Delete orphaned VolumeAttachments (dry-run by default)'
)
@click.option(
    '--output',
    type=click.Choice(['human', 'json'], case_sensitive=False),
    default='human',
    help='Output format'
)
@click.option(
    '--yes',
    is_flag=True,
    help='Skip confirmation prompts'
)
@click.option(
    '--verbose',
    is_flag=True,
    help='Enable verbose logging'
)
def main(delete: bool, output: str, yes: bool, verbose: bool) -> None:
    
    # Configure logging
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    try:
        # Load configuration
        config_dict = ConfigValidator.load_config()

        # Initialize clients
        k8s_client = KubernetesClient(context=config_dict['k8s_context'] or None)
        validator = VolumeAttachmentValidator(
            k8s_client=k8s_client,
            compartment_id=config_dict['compartment_id']
        )

        # Perform validation
        report = validator.validate()

        # Output report
        if output == 'json':
            print_json_report(report)
        else:
            print_human_report(report)

        # Cleanup if requested
        if delete:
            if not report.orphaned_attachments:
                click.echo("No orphaned attachments to delete.", err=True)
                sys.exit(0)

            click.echo(f"\n🗑️  Starting cleanup of {len(report.orphaned_attachments)} attachments...\n")
            results = validator.cleanup_orphaned(
                report.orphaned_attachments,
                skip_confirmation=yes
            )

            click.echo(f"\n✅ Cleanup complete:")
            click.echo(f"   Deleted: {results['deleted']}")
            click.echo(f"   Failed: {results['failed']}")
            click.echo(f"   Skipped: {results['skipped']}\n")

            # Exit with error if any deletions failed
            if results['failed'] > 0:
                sys.exit(1)

        # Exit with error code if orphaned attachments found (for CI/CD)
        if report.orphaned_attachments and not delete:
            sys.exit(1)

        sys.exit(0)

    except ValueError as e:
        click.echo(f"❌ Configuration error: {e}", err=True)
        sys.exit(2)
    except ApiException as e:
        click.echo(f"❌ Kubernetes API error: {e.reason}", err=True)
        sys.exit(3)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(4)


if __name__ == '__main__':
    main()
