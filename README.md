# Small_Dense_Subgraphs
Let G = (V,E) be an undirected graph. For any subset of vertices V' from V, the density "rho" of the subgraph induced by V is defined as: rho(V') = |E[V']|/V',  
where |E[V']| subset of E is the set of edges whose endpoints lie in V'. In this problem we are asked to design and implement a MapReduce algorithm that, given a density rho, finds a subgraph of G with density >= rho, i.e., a set V' such that rho(V') >= rho. The challenge is to find a subgraph that is as small as possible. While the problem of finding the smallest dense-enough subgraph is hard, we should attempt at finding a subgraph with density >= rho as small as we can.  
Several real-world graphs on which we can test our algorithms can be downloaded from the SNAP (Stanford Network Analysis Project) website: http://snap.stanford.edu/. Some of these graphs are directed, in which case one should take care of preprocessing them so that they are regarded as undirected in the algorithm.  
  
The problem is divided into 3 basic steps:  
1. Compute the density of the whole original graph, "ComputeGraphDensity" class;  
2. Use the just computed density as a threshold for both pruning and partitioning of the graph, "GraphPartitioning" class;  
3. Find the smallest subgraph with the corresponding degree threshold (rho value), "ComputeMinDensitySubgraph" class.  
  
Each step is translated in a corresponding MapReduce round:  
 1. For the first round the Mapper just parses the input graph file, line by line (edge by edge). All the edges are being transferred to only one Reducer.  
The Reducer computes the density of the whole graph, iterating over the edges and keeping track of the nr of edges and nodes. The output file produced by this Reducer is of the following form:

        ###############################################
        #     [src]<tab>[dst]<tab>[graph_density]     #
        # ... [src]<tab>[dst]<tab>[graph_density] ... #  
        # ........................................... #  
        ###############################################
  
 2. In the second round the Mapper parses the output file, line by line, produced by the previous  MapReduce round. For each parsed line, emits a <subgraphID, edge> keyvalue pair, randomly choosing the “subgraphID” in [0 graph_density) range.  
The Reducer receives as input a \<subgraphID, List\<edge\>\> keyvalue pair, which corresponds to the  specific “subgraphID” subgraph of the original graph. For each edge of the corresponding subgraph, it explores the degrees (in the subgraph’s context) of both edge’s endpoints, and emits the edge only if the degrees of the both endpoints are greater than graph_density.  
This round is very important to the success of the entire algorithm because: first, the algorithm takes advantage of parallelized computation (subgraph pruning is done in each graph partition); and second, it throws away edges which endpoints have very few links (endpoint_degree < graph_density), and thus nodes with small degree that don’t contribute as much to the final desired result, are pruned.  
In sum, the purpose of the round is to cross out those nodes that don’t contribute to the result, and, the output are the edges which endpoints are more suitable to help us in the task.

 3. In this round the Mapper just parses the partitioned input graph file, produced by the previous MapReduce round, line by line (edge by edge), and outputs all the edges with the same key so that they are transferred to only one Reducer.  
The Reducer iterates over all the nodes, and at each iteration it removes from the graph the node with the minimum degree. Then it computes the new graph density and if the new graph is better, it stores the new best density of at least rho and the new best graph. This will continue until all nodes have been removed from the graph and in the end we will have stored the smallest graph of at least density rho the algorithm could find.
