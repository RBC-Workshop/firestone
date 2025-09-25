"""
Multi-cluster Kubernetes API client wrapper for monty utility.
"""
import logging
from typing import Dict, List, Optional, Any
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import yaml
import os


logger = logging.getLogger(__name__)


class KubernetesClientError(Exception):
    """Custom exception for Kubernetes client errors."""
    pass


class MultiClusterKubernetesClient:
    """Multi-cluster Kubernetes API client manager."""
    
    def __init__(self, cluster_configs: List[Dict[str, Any]]):
        """
        Initialize multi-cluster Kubernetes client.
        
        Args:
            cluster_configs: List of cluster configuration dictionaries
        """
        self.clusters = {}
        self.cluster_configs = cluster_configs
        
        for cluster_config in cluster_configs:
            try:
                cluster_name = cluster_config['name']
                self.clusters[cluster_name] = self._create_client(cluster_config)
                logger.info(f"Successfully initialized client for cluster: {cluster_name}")
            except Exception as e:
                logger.error(f"Failed to initialize client for cluster {cluster_config.get('name', 'unknown')}: {e}")
    
    def _create_client(self, cluster_config: Dict[str, Any]) -> client.CoreV1Api:
        """
        Create Kubernetes API client for a specific cluster.
        
        Args:
            cluster_config: Cluster configuration dictionary
            
        Returns:
            Kubernetes CoreV1Api client
        """
        configuration = client.Configuration()
        configuration.host = cluster_config['endpoint']
        
        if cluster_config.get('ca_cert_path'):
            configuration.ssl_ca_cert = cluster_config['ca_cert_path']
        
        configuration.verify_ssl = cluster_config.get('verify_ssl', True)
        
        if cluster_config.get('service_account_token_path'):
            with open(cluster_config['service_account_token_path'], 'r') as f:
                token = f.read().strip()
            configuration.api_key = {"authorization": f"Bearer {token}"}
        elif cluster_config.get('kubeconfig_path'):
            config.load_kube_config(
                config_file=cluster_config['kubeconfig_path'],
                client_configuration=configuration
            )
        
        api_client = client.ApiClient(configuration)
        return client.CoreV1Api(api_client)
    
    def get_cluster_client(self, cluster_name: str) -> client.CoreV1Api:
        """
        Get Kubernetes client for specific cluster.
        
        Args:
            cluster_name: Name of the cluster
            
        Returns:
            Kubernetes CoreV1Api client
            
        Raises:
            KubernetesClientError: If cluster not found
        """
        if cluster_name not in self.clusters:
            raise KubernetesClientError(f"Cluster '{cluster_name}' not configured")
        
        return self.clusters[cluster_name]
    
    def list_namespaces(self, cluster_name: str, label_selector: Optional[str] = None,
                       limit: Optional[int] = None, offset: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        List namespaces in a specific cluster.
        
        Args:
            cluster_name: Target cluster name
            label_selector: Label selector for filtering
            limit: Maximum number of namespaces to return
            offset: Offset for pagination
            
        Returns:
            List of namespace dictionaries
        """
        try:
            k8s_client = self.get_cluster_client(cluster_name)
            
            namespaces_list = k8s_client.list_namespace(
                label_selector=label_selector,
                limit=limit
            )
            
            namespaces = []
            for i, ns in enumerate(namespaces_list.items):
                if offset and i < offset:
                    continue
                
                namespace_dict = self._namespace_to_dict(ns, cluster_name)
                namespaces.append(namespace_dict)
            
            logger.info(f"Listed {len(namespaces)} namespaces from cluster {cluster_name}")
            return namespaces
            
        except ApiException as e:
            logger.error(f"Kubernetes API error listing namespaces in {cluster_name}: {e}")
            raise KubernetesClientError(f"Failed to list namespaces: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error listing namespaces in {cluster_name}: {e}")
            raise KubernetesClientError(f"Unexpected error: {str(e)}")
    
    def get_namespace(self, cluster_name: str, namespace_name: str) -> Dict[str, Any]:
        """
        Get specific namespace from cluster.
        
        Args:
            cluster_name: Target cluster name
            namespace_name: Name of the namespace
            
        Returns:
            Namespace dictionary
        """
        try:
            k8s_client = self.get_cluster_client(cluster_name)
            
            namespace = k8s_client.read_namespace(name=namespace_name)
            namespace_dict = self._namespace_to_dict(namespace, cluster_name)
            
            logger.info(f"Retrieved namespace {namespace_name} from cluster {cluster_name}")
            return namespace_dict
            
        except ApiException as e:
            if e.status == 404:
                raise KubernetesClientError(f"Namespace '{namespace_name}' not found")
            logger.error(f"Kubernetes API error getting namespace {namespace_name}: {e}")
            raise KubernetesClientError(f"Failed to get namespace: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error getting namespace {namespace_name}: {e}")
            raise KubernetesClientError(f"Unexpected error: {str(e)}")
    
    def create_namespace(self, cluster_name: str, namespace_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create namespace in cluster.
        
        Args:
            cluster_name: Target cluster name
            namespace_data: Namespace creation data
            
        Returns:
            Created namespace dictionary
        """
        try:
            k8s_client = self.get_cluster_client(cluster_name)
            
            namespace = client.V1Namespace(
                metadata=client.V1ObjectMeta(
                    name=namespace_data['namespace_name'],
                    labels=namespace_data.get('labels', {}),
                    annotations=namespace_data.get('annotations', {})
                )
            )
            
            created_namespace = k8s_client.create_namespace(body=namespace)
            
            if namespace_data.get('resource_quota'):
                self._create_resource_quota(
                    k8s_client, 
                    namespace_data['namespace_name'],
                    namespace_data['resource_quota']
                )
            
            namespace_dict = self._namespace_to_dict(created_namespace, cluster_name)
            logger.info(f"Created namespace {namespace_data['namespace_name']} in cluster {cluster_name}")
            return namespace_dict
            
        except ApiException as e:
            if e.status == 409:
                raise KubernetesClientError(f"Namespace '{namespace_data['namespace_name']}' already exists")
            logger.error(f"Kubernetes API error creating namespace: {e}")
            raise KubernetesClientError(f"Failed to create namespace: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error creating namespace: {e}")
            raise KubernetesClientError(f"Unexpected error: {str(e)}")
    
    def update_namespace(self, cluster_name: str, namespace_name: str, 
                        namespace_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update namespace in cluster.
        
        Args:
            cluster_name: Target cluster name
            namespace_name: Name of the namespace to update
            namespace_data: Updated namespace data
            
        Returns:
            Updated namespace dictionary
        """
        try:
            k8s_client = self.get_cluster_client(cluster_name)
            
            current_namespace = k8s_client.read_namespace(name=namespace_name)
            
            if namespace_data.get('labels'):
                current_namespace.metadata.labels = namespace_data['labels']
            if namespace_data.get('annotations'):
                current_namespace.metadata.annotations = namespace_data['annotations']
            
            updated_namespace = k8s_client.patch_namespace(
                name=namespace_name,
                body=current_namespace
            )
            
            if namespace_data.get('resource_quota'):
                self._update_resource_quota(
                    k8s_client,
                    namespace_name,
                    namespace_data['resource_quota']
                )
            
            namespace_dict = self._namespace_to_dict(updated_namespace, cluster_name)
            logger.info(f"Updated namespace {namespace_name} in cluster {cluster_name}")
            return namespace_dict
            
        except ApiException as e:
            if e.status == 404:
                raise KubernetesClientError(f"Namespace '{namespace_name}' not found")
            logger.error(f"Kubernetes API error updating namespace {namespace_name}: {e}")
            raise KubernetesClientError(f"Failed to update namespace: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error updating namespace {namespace_name}: {e}")
            raise KubernetesClientError(f"Unexpected error: {str(e)}")
    
    def delete_namespace(self, cluster_name: str, namespace_name: str) -> bool:
        """
        Delete namespace from cluster.
        
        Args:
            cluster_name: Target cluster name
            namespace_name: Name of the namespace to delete
            
        Returns:
            True if deletion was initiated successfully
        """
        try:
            k8s_client = self.get_cluster_client(cluster_name)
            
            k8s_client.delete_namespace(name=namespace_name)
            
            logger.info(f"Initiated deletion of namespace {namespace_name} in cluster {cluster_name}")
            return True
            
        except ApiException as e:
            if e.status == 404:
                raise KubernetesClientError(f"Namespace '{namespace_name}' not found")
            logger.error(f"Kubernetes API error deleting namespace {namespace_name}: {e}")
            raise KubernetesClientError(f"Failed to delete namespace: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error deleting namespace {namespace_name}: {e}")
            raise KubernetesClientError(f"Unexpected error: {str(e)}")
    
    def _namespace_to_dict(self, namespace: client.V1Namespace, cluster_name: str) -> Dict[str, Any]:
        """
        Convert Kubernetes namespace object to dictionary.
        
        Args:
            namespace: Kubernetes V1Namespace object
            cluster_name: Name of the cluster
            
        Returns:
            Namespace dictionary
        """
        return {
            'namespace_name': namespace.metadata.name,
            'cluster_name': cluster_name,
            'labels': namespace.metadata.labels or {},
            'annotations': namespace.metadata.annotations or {},
            'status': namespace.status.phase if namespace.status else 'Unknown',
            'created_at': namespace.metadata.creation_timestamp.isoformat() if namespace.metadata.creation_timestamp else None,
            'resource_quota': self._get_resource_quota(cluster_name, namespace.metadata.name),
            'network_policies': [],  # TODO: Implement network policy retrieval
            'created_by': namespace.metadata.annotations.get('created-by', 'unknown') if namespace.metadata.annotations else 'unknown',
            'ad_groups': []  # TODO: Implement AD group retrieval from annotations
        }
    
    def _create_resource_quota(self, k8s_client: client.CoreV1Api, 
                              namespace_name: str, quota_spec: Dict[str, Any]):
        """
        Create resource quota for namespace.
        
        Args:
            k8s_client: Kubernetes API client
            namespace_name: Target namespace
            quota_spec: Resource quota specification
        """
        try:
            hard_limits = {}
            if quota_spec.get('cpu_limit'):
                hard_limits['requests.cpu'] = quota_spec['cpu_limit']
                hard_limits['limits.cpu'] = quota_spec['cpu_limit']
            if quota_spec.get('memory_limit'):
                hard_limits['requests.memory'] = quota_spec['memory_limit']
                hard_limits['limits.memory'] = quota_spec['memory_limit']
            if quota_spec.get('storage_limit'):
                hard_limits['requests.storage'] = quota_spec['storage_limit']
            if quota_spec.get('pod_limit'):
                hard_limits['count/pods'] = str(quota_spec['pod_limit'])
            
            if not hard_limits:
                return
            
            quota = client.V1ResourceQuota(
                metadata=client.V1ObjectMeta(
                    name=f"{namespace_name}-quota",
                    namespace=namespace_name
                ),
                spec=client.V1ResourceQuotaSpec(hard=hard_limits)
            )
            
            k8s_client.create_namespaced_resource_quota(
                namespace=namespace_name,
                body=quota
            )
            
            logger.info(f"Created resource quota for namespace {namespace_name}")
            
        except ApiException as e:
            logger.warning(f"Failed to create resource quota for {namespace_name}: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error creating resource quota for {namespace_name}: {e}")
    
    def _update_resource_quota(self, k8s_client: client.CoreV1Api,
                              namespace_name: str, quota_spec: Dict[str, Any]):
        """
        Update resource quota for namespace.
        
        Args:
            k8s_client: Kubernetes API client
            namespace_name: Target namespace
            quota_spec: Updated resource quota specification
        """
        try:
            quota_name = f"{namespace_name}-quota"
            
            try:
                existing_quota = k8s_client.read_namespaced_resource_quota(
                    name=quota_name,
                    namespace=namespace_name
                )
            except ApiException as e:
                if e.status == 404:
                    self._create_resource_quota(k8s_client, namespace_name, quota_spec)
                    return
                raise
            
            hard_limits = {}
            if quota_spec.get('cpu_limit'):
                hard_limits['requests.cpu'] = quota_spec['cpu_limit']
                hard_limits['limits.cpu'] = quota_spec['cpu_limit']
            if quota_spec.get('memory_limit'):
                hard_limits['requests.memory'] = quota_spec['memory_limit']
                hard_limits['limits.memory'] = quota_spec['memory_limit']
            if quota_spec.get('storage_limit'):
                hard_limits['requests.storage'] = quota_spec['storage_limit']
            if quota_spec.get('pod_limit'):
                hard_limits['count/pods'] = str(quota_spec['pod_limit'])
            
            existing_quota.spec.hard = hard_limits
            
            k8s_client.patch_namespaced_resource_quota(
                name=quota_name,
                namespace=namespace_name,
                body=existing_quota
            )
            
            logger.info(f"Updated resource quota for namespace {namespace_name}")
            
        except Exception as e:
            logger.warning(f"Failed to update resource quota for {namespace_name}: {e}")
    
    def _get_resource_quota(self, cluster_name: str, namespace_name: str) -> Dict[str, Any]:
        """
        Get resource quota for namespace.
        
        Args:
            cluster_name: Target cluster name
            namespace_name: Target namespace
            
        Returns:
            Resource quota dictionary
        """
        try:
            k8s_client = self.get_cluster_client(cluster_name)
            quota_name = f"{namespace_name}-quota"
            
            quota = k8s_client.read_namespaced_resource_quota(
                name=quota_name,
                namespace=namespace_name
            )
            
            hard_limits = quota.spec.hard or {}
            
            return {
                'cpu_limit': hard_limits.get('limits.cpu'),
                'memory_limit': hard_limits.get('limits.memory'),
                'storage_limit': hard_limits.get('requests.storage'),
                'pod_limit': int(hard_limits.get('count/pods', 0)) if hard_limits.get('count/pods') else None
            }
            
        except ApiException as e:
            if e.status == 404:
                return {}
            logger.warning(f"Failed to get resource quota for {namespace_name}: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Unexpected error getting resource quota for {namespace_name}: {e}")
            return {}
    
    def get_available_clusters(self) -> List[str]:
        """
        Get list of available cluster names.
        
        Returns:
            List of cluster names
        """
        return list(self.clusters.keys())
    
    def health_check(self, cluster_name: str) -> bool:
        """
        Check if cluster is accessible.
        
        Args:
            cluster_name: Target cluster name
            
        Returns:
            True if cluster is accessible
        """
        try:
            k8s_client = self.get_cluster_client(cluster_name)
            k8s_client.list_namespace(limit=1)
            return True
        except Exception as e:
            logger.error(f"Health check failed for cluster {cluster_name}: {e}")
            return False
