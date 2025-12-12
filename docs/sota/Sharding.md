Dans **ce contexte précis**, *sharding* désigne une **technique pour répartir une grosse structure de données (ici, le dictionnaire D du meet‑in‑the‑middle) entre plusieurs machines ou plusieurs processus**, afin d’éviter qu’un seul nœud ne supporte toute la charge mémoire et toute la charge de requêtes.

---

# Sharding — explication simple

Sharder = **découper** (to shard → to split into shards).

Tu prends une *grosse table de hachage* (le dictionnaire D du MITM) qui contient jusqu’à (2^n) entrées, et tu la **partages en plusieurs morceaux**, appelés *shards*, chacun stocké sur un nœud différent :

```
Cluster
 ├── Node 0  → shard 0
 ├── Node 1  → shard 1
 ├── Node 2  → shard 2
 └── Node 3  → shard 3
```

Chaque machine ne stocke **qu’une partie** du dictionnaire.

---

# Pourquoi on en a besoin ici ?

Dans la phase “forward” :

```
Pour chaque x, calculer f(x) et insérer (f(x) → x) dans D
```

Si n ≈ 40, tu as :

* (2^{40} ≈ 10^{12}) entrées,
* mémoire requise : de l’ordre de **térabytes** → impossible sur une seule machine.

Donc on répartit D sur beaucoup de nœuds.

---

# Comment répartir les données ? (La vraie définition du sharding)

La technique la plus courante :

## 1. Sharding par hash de la clé

Tu choisis une *clé* = la valeur f(x), et tu définis :

```
shard_id = hash(f(x)) mod N
```

Avec N = nombre de nœuds.

* À l’insertion : tu envoies f(x) au nœud `shard_id`
* À la recherche (lors du “lookup” de g(y)) :

  * tu calcules le même hash,
  * tu vas interroger **directement le bon nœud**.

Le gros avantage :
**pas besoin de broadcast**.
Tu sais exactement où se trouve la donnée.

---

# Ce que ça donne dans ton MITM distribué

## Phase 1 : construction de D distribuée

Chaque processus fait :

```
for (x):
    k = f(x)
    shard = hash(k) % N
    envoyer (k → x) au nœud "shard"
```

Chaque nœud stocke seulement son shard.

## Phase 2 : recherche

Pour chaque y :

```
k = g(y)
shard = hash(k) % N
envoyer k au bon nœud
récupérer les x stockés
tester π(x, y)
```

---

# Pourquoi "sinon c'est l'enfer" ?

Sans sharding, on aurait :

* soit un dictionnaire unique → impossible (mémoire),
* soit chaque lookup devrait interroger **toutes** les machines (broadcast), soit N fois plus d’échanges réseau → carrement impossible en performance.

Avec sharding :

✔ mémoire divisée par N
✔ lookup constant (1 seul nœud ciblé)
✔ scalable sur 10, 50 ou 100 nœuds

C’est exactement ce que font :
Cassandra, Bigtable, Dynamo, MongoDB en mode cluster…
