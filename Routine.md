# Routine

## Aller sur Nancy:
ssh nancy.g5k

## Compiler un code:
mpicc -O3 -Wall -fopenmp mitm_mpi.c -o mitm_mpi

## Exécuter un code:
mpirun -machinefile $OAR_NODEFILE -np 8 ./mitm_mpi --n 20 --C0 ab608b105290528d --C1 03abc7b389f440ed

## Envoyer un code local -> nancy:
scp mitm.c apanguel@nancy.g5k:/home/apanguel/projet/

## Envoyer un code nancy -> local:
scp apanguel@nancy.g5k:/home/apanguel/projet/mitm.c .

## Lancer le mitm.c:
./mitm --n 20 --C0 ab608b105290528d --C1 03abc7b389f440ed

## Réserver des noeuds gros
oarsub -I -l nodes=2,walltime=3:00:00

## Avec le Makefile

### Compilation
make

### Exécution
make run ARGS="--n 30 --C0 f5ab93c4313512dd --C1 33876ac77f205cd5"