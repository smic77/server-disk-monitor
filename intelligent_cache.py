#!/usr/bin/env python3
"""
Système de cache intelligent pour Server Disk Monitor
Optimise les performances en évitant les requêtes SSH répétitives inutiles
"""

import time
import threading
from typing import Dict, Any, Optional, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import logging
import hashlib
import json

logger = logging.getLogger(__name__)

class CacheStrategy(Enum):
    """Stratégies de mise en cache"""
    AGGRESSIVE = "aggressive"      # Cache longtemps, idéal pour données stables
    BALANCED = "balanced"         # Équilibre entre fraîcheur et performance  
    CONSERVATIVE = "conservative" # Cache peu, privilégie la fraîcheur
    ADAPTIVE = "adaptive"        # S'adapte selon le comportement des données

@dataclass
class CacheEntry:
    """Entrée de cache avec métadonnées"""
    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int
    ttl_seconds: int
    strategy: CacheStrategy
    
    # Métadonnées pour l'adaptabilité
    change_frequency: float = 0.0  # Fréquence de changement observée
    importance_score: float = 1.0  # Importance relative (0-1)
    
    def is_expired(self) -> bool:
        """Vérifie si l'entrée a expiré"""
        return datetime.now() > (self.created_at + timedelta(seconds=self.ttl_seconds))
    
    def is_stale(self, staleness_threshold: int = None) -> bool:
        """Vérifie si l'entrée est obsolète selon un seuil personnalisé"""
        if staleness_threshold is None:
            return self.is_expired()
        
        return datetime.now() > (self.created_at + timedelta(seconds=staleness_threshold))
    
    def age_seconds(self) -> int:
        """Âge de l'entrée en secondes"""
        return int((datetime.now() - self.created_at).total_seconds())
    
    def access(self):
        """Marque l'entrée comme accédée"""
        self.last_accessed = datetime.now()
        self.access_count += 1

class IntelligentCache:
    """Cache intelligent avec stratégies adaptatives"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        
        # Statistiques
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        
        # Verrou pour thread-safety
        self.lock = threading.RLock()
        
        # Configuration des stratégies TTL
        self.strategy_ttl = {
            CacheStrategy.AGGRESSIVE: 1800,    # 30 minutes
            CacheStrategy.BALANCED: 300,       # 5 minutes
            CacheStrategy.CONSERVATIVE: 60,    # 1 minute
            CacheStrategy.ADAPTIVE: 300        # Base 5 minutes, ajusté dynamiquement
        }
        
        # Nettoyage périodique
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_running = True
        self.cleanup_thread.start()
        
        logger.info(f"Cache intelligent initialisé (taille max: {max_size})")
    
    def _generate_key(self, base_key: str, **kwargs) -> str:
        """Génère une clé de cache unique et déterministe"""
        # Inclure les paramètres dans la clé pour éviter les collisions
        if kwargs:
            param_str = json.dumps(kwargs, sort_keys=True, separators=(',', ':'))
            combined = f"{base_key}::{param_str}"
        else:
            combined = base_key
        
        # Hasher pour éviter les clés trop longues
        return hashlib.md5(combined.encode()).hexdigest()[:16] + f"__{base_key}"
    
    def get(self, key: str, default=None, **kwargs) -> Any:
        """Récupère une valeur du cache"""
        cache_key = self._generate_key(key, **kwargs)
        
        with self.lock:
            if cache_key in self.cache:
                entry = self.cache[cache_key]
                
                if not entry.is_expired():
                    entry.access()
                    self.hits += 1
                    logger.debug(f"Cache HIT: {key} (age: {entry.age_seconds()}s)")
                    return entry.value
                else:
                    # Entrée expirée
                    del self.cache[cache_key]
                    logger.debug(f"Cache EXPIRED: {key}")
            
            self.misses += 1
            logger.debug(f"Cache MISS: {key}")
            return default
    
    def set(self, key: str, value: Any, strategy: CacheStrategy = CacheStrategy.BALANCED, 
            importance: float = 1.0, **kwargs):
        """Stocke une valeur dans le cache"""
        cache_key = self._generate_key(key, **kwargs)
        
        with self.lock:
            # Déterminer le TTL selon la stratégie
            if strategy == CacheStrategy.ADAPTIVE:
                ttl = self._calculate_adaptive_ttl(cache_key, importance)
            else:
                ttl = self.strategy_ttl[strategy]
            
            # Créer l'entrée
            entry = CacheEntry(
                key=cache_key,
                value=value,
                created_at=datetime.now(),
                last_accessed=datetime.now(),
                access_count=1,
                ttl_seconds=ttl,
                strategy=strategy,
                importance_score=importance
            )
            
            # Vérifier si c'est un changement par rapport à l'ancienne valeur
            if cache_key in self.cache:
                old_entry = self.cache[cache_key]
                # Calculer la fréquence de changement pour l'adaptabilité
                if old_entry.value != value:
                    entry.change_frequency = self._calculate_change_frequency(old_entry)
            
            # Éviction si nécessaire
            if len(self.cache) >= self.max_size:
                self._evict_entries()
            
            self.cache[cache_key] = entry
            logger.debug(f"Cache SET: {key} (TTL: {ttl}s, strategy: {strategy.value})")
    
    def _calculate_adaptive_ttl(self, cache_key: str, importance: float) -> int:
        """Calcule un TTL adaptatif basé sur l'historique"""
        base_ttl = self.strategy_ttl[CacheStrategy.ADAPTIVE]
        
        if cache_key in self.cache:
            old_entry = self.cache[cache_key]
            
            # Si les données changent souvent, réduire le TTL
            if old_entry.change_frequency > 0.5:
                base_ttl = int(base_ttl * 0.5)  # Réduire de moitié
            elif old_entry.change_frequency < 0.1:
                base_ttl = int(base_ttl * 2)    # Doubler si stable
            
            # Ajuster selon l'importance
            base_ttl = int(base_ttl * importance)
        
        return max(30, min(3600, base_ttl))  # Entre 30 secondes et 1 heure
    
    def _calculate_change_frequency(self, old_entry: CacheEntry) -> float:
        """Calcule la fréquence de changement des données"""
        age_hours = old_entry.age_seconds() / 3600.0
        if age_hours < 0.1:  # Moins de 6 minutes
            return 1.0  # Changement très fréquent
        
        # Simple métrique : 1 changement / âge en heures
        return min(1.0, 1.0 / age_hours)
    
    def _evict_entries(self):
        """Éviction intelligente d'entrées selon plusieurs critères"""
        if not self.cache:
            return
        
        # Stratégies d'éviction par priorité:
        # 1. Entrées expirées
        # 2. Entrées peu importantes et peu accédées
        # 3. Entrées les plus anciennes
        
        expired_keys = [
            key for key, entry in self.cache.items() 
            if entry.is_expired()
        ]
        
        if expired_keys:
            for key in expired_keys:
                del self.cache[key]
                self.evictions += 1
            logger.debug(f"Éviction: {len(expired_keys)} entrées expirées")
            return
        
        # Si toujours trop d'entrées, éviction par score
        if len(self.cache) >= self.max_size:
            # Calculer un score d'éviction (plus bas = éviction prioritaire)
            entries_with_scores = []
            for key, entry in self.cache.items():
                # Score basé sur: importance, fréquence d'accès, âge
                access_freq = entry.access_count / max(1, entry.age_seconds() / 3600)
                score = (entry.importance_score * 0.4 + 
                        access_freq * 0.4 + 
                        (1.0 - min(1.0, entry.age_seconds() / 3600)) * 0.2)
                entries_with_scores.append((score, key))
            
            # Trier par score croissant et supprimer les moins importantes
            entries_with_scores.sort()
            entries_to_evict = len(self.cache) - self.max_size + 1
            
            for i in range(entries_to_evict):
                if i < len(entries_with_scores):
                    _, key = entries_with_scores[i]
                    del self.cache[key]
                    self.evictions += 1
            
            logger.debug(f"Éviction: {entries_to_evict} entrées par score")
    
    def invalidate(self, key_pattern: str = None, **kwargs):
        """Invalide des entrées du cache"""
        with self.lock:
            if key_pattern is None:
                # Vider tout le cache
                cleared = len(self.cache)
                self.cache.clear()
                logger.info(f"Cache vidé: {cleared} entrées supprimées")
            else:
                # Invalider les entrées correspondant au pattern
                cache_key_pattern = self._generate_key(key_pattern, **kwargs)
                keys_to_remove = [
                    key for key in self.cache.keys() 
                    if key_pattern in key or key.endswith(key_pattern)
                ]
                
                for key in keys_to_remove:
                    del self.cache[key]
                
                logger.debug(f"Cache invalidé: {len(keys_to_remove)} entrées pour '{key_pattern}'")
    
    def cache_or_compute(self, key: str, compute_func: Callable, 
                        strategy: CacheStrategy = CacheStrategy.BALANCED, 
                        importance: float = 1.0, **kwargs) -> Any:
        """Pattern cache-aside: récupère du cache ou calcule et met en cache"""
        
        # Essayer de récupérer du cache
        cached_value = self.get(key, **kwargs)
        if cached_value is not None:
            return cached_value
        
        # Calculer la valeur
        try:
            computed_value = compute_func()
            
            # Mettre en cache si la computation a réussi
            if computed_value is not None:
                self.set(key, computed_value, strategy, importance, **kwargs)
            
            return computed_value
        
        except Exception as e:
            logger.error(f"Erreur computation pour cache key '{key}': {e}")
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistiques du cache"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            
            # Analyse des stratégies
            strategy_distribution = {}
            for entry in self.cache.values():
                strategy = entry.strategy.value
                strategy_distribution[strategy] = strategy_distribution.get(strategy, 0) + 1
            
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'evictions': self.evictions,
                'hit_rate_percent': round(hit_rate, 2),
                'strategy_distribution': strategy_distribution,
                'memory_usage_mb': self._estimate_memory_usage()
            }
    
    def _estimate_memory_usage(self) -> float:
        """Estimation approximative de l'usage mémoire en MB"""
        import sys
        
        total_size = 0
        for entry in self.cache.values():
            total_size += sys.getsizeof(entry.key)
            total_size += sys.getsizeof(entry.value)
            total_size += sys.getsizeof(entry)
        
        return round(total_size / (1024 * 1024), 2)
    
    def _cleanup_loop(self):
        """Boucle de nettoyage périodique"""
        while self.cleanup_running:
            try:
                time.sleep(300)  # Nettoyage toutes les 5 minutes
                
                with self.lock:
                    expired_keys = [
                        key for key, entry in self.cache.items()
                        if entry.is_expired()
                    ]
                    
                    for key in expired_keys:
                        del self.cache[key]
                        self.evictions += 1
                    
                    if expired_keys:
                        logger.debug(f"Nettoyage automatique: {len(expired_keys)} entrées expirées")
                
            except Exception as e:
                logger.error(f"Erreur nettoyage cache: {e}")
    
    def shutdown(self):
        """Arrête le cache et nettoie les ressources"""
        self.cleanup_running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=1)
        
        with self.lock:
            self.cache.clear()
        
        logger.info("Cache intelligent fermé")

class DiskMonitorCache(IntelligentCache):
    """Cache spécialisé pour le monitoring des disques"""
    
    def __init__(self):
        super().__init__(max_size=5000, default_ttl=300)
        
        # Stratégies spécialisées pour différents types de données
        self.data_strategies = {
            'disk_status': CacheStrategy.BALANCED,      # Status disques: équilibré
            'server_ping': CacheStrategy.CONSERVATIVE,  # Ping serveur: fraîcheur importante
            'disk_info': CacheStrategy.AGGRESSIVE,      # Info disques: change rarement
            'ssh_connection': CacheStrategy.ADAPTIVE    # Connexions SSH: adaptatif
        }
    
    def cache_disk_status(self, server_ip: str, device: str, status: Dict[str, Any]):
        """Cache le statut d'un disque"""
        key = f"disk_status_{server_ip}_{device}"
        self.set(key, status, self.data_strategies['disk_status'], importance=0.8)
    
    def get_disk_status(self, server_ip: str, device: str) -> Optional[Dict[str, Any]]:
        """Récupère le statut d'un disque du cache"""
        key = f"disk_status_{server_ip}_{device}"
        return self.get(key)
    
    def cache_server_ping(self, server_ip: str, is_online: bool):
        """Cache le résultat d'un ping serveur"""
        key = f"server_ping_{server_ip}"
        self.set(key, is_online, self.data_strategies['server_ping'], importance=1.0)
    
    def get_server_ping(self, server_ip: str) -> Optional[bool]:
        """Récupère le statut de ping d'un serveur"""
        key = f"server_ping_{server_ip}"
        return self.get(key)
    
    def invalidate_server_cache(self, server_ip: str):
        """Invalide tout le cache d'un serveur spécifique"""
        self.invalidate(f"disk_status_{server_ip}")
        self.invalidate(f"server_ping_{server_ip}")
        self.invalidate(f"ssh_connection_{server_ip}")

# Instance globale pour l'application
disk_cache = DiskMonitorCache()