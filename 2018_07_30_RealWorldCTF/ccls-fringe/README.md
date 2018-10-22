# Real World CTF 2018: ccls-fringe (forensics, 146 pts)
###### By @Vtec234

The challenge reads:

> Ray said that the challenge "Leaf-Similar Trees" from last LeetCode Weekly was really same-fringe problem and wrote it in the form of coroutine which he learned from a Stanford friend. Can you decrypt the cache file dumped from a language server without reading the source code? The flag is not in the form of rwctf{} because special characters cannot be used.

And we get a zip containing the file `.ccls-cache/@home@flag@/fringe.cc.blob`.

## WTF is.. ccls?

The file we got, `fringe.cc.blob` is some sort of binary blob. A quick search reveals that it's the index cache for a [C-family language server](https://github.com/MaskRay/ccls). A bit less quick dig through the sources reveals that `ccls` is clang-based, and stores certain elements of the AST largely unchanged in the cache.

For example, clang uses [Unified Symbol Resolution (`Usr`)](https://clang.llvm.org/doxygen/group__CINDEX__CURSOR__XREF.html) identifiers to uniquely name elements such as types, variables, and functions - these are also present in the cache. Reading through binary files is not the most pleasant thing in the world - it would be nice if we could look at a more structured representation of the data.

Luckily, the tool happens to have support for two serialization backends - binary, used here, and JSON. A simple modification to the code allows us to read in the binary file and dump it again as JSON.

The JSON contains some metadata, and more interestingly, maps from `Usr`s to various objects:
```json
  "usr2func": [
    {
      "usr": 1676767203992940432,
      "detailed_name": "bool std::solution::leafsimilar(std::treenode *root1, std::treenode *root2)",
      "qual_name_offset": 5,
      "short_name_offset": 20,
      "short_name_size": 11,
      "kind": 6,
      "storage": 0,
      "hover": "",
      "comments": "",
      "declarations": [],
      "spell": "38:8-38:19|59306568996318058|2|514",
      "extent": "38:3-46:4|59306568996318058|2|0",
      "bases": [],
      "derived": [],
      "vars": [
        4479758688836879116,
        ...
      ],
      "uses": [],
      "callees": [
        "40:8-40:10|1935187987660993811|3|8484",
        ...
      ]
    },
    ...
```

I went looking through the JSON in more detail to understand its structure. Seeing nothing like an obvious flag, I initially thought there might be a reverse engineering element, where the described program actually checks user input and returns `true` if it's the flag. But how would that work given this part of the description?

> The flag is not in the form of rwctf{} because special characters cannot be used.

Maybe it _is_ in the source after all, hidden within identifiers. I decided to reconstruct some of the original source and see what it looks like. To do so, I modified the `ccls` main function and used its parsed representation of the index:

```cpp
int main(int argc, char** argv) {
  TraceMe();
  sys::PrintStackTraceOnErrorSignal(argv[0]);

  g_config = new Config;
  g_config->projectRoot = std::string("home/flag/");
  g_config->cacheDirectory = std::string("./");
  g_config->cacheFormat = SerializeFormat::Binary;

  std::unique_ptr<IndexFile> fidx =
    ccls::pipeline::RawCacheLoad("fringe.cc");

  // namespace std
  //auto ns = fidx->usr2type[5401847601697785946];

  // Reproduction of the original file
  std::vector<std::string> repro(256, std::string(512, ' '));

  for (std::pair<Usr, IndexVar> const& p : fidx->usr2var) {
    VarDef const& var = p.second.def;
    if (var.extent) {
      int16_t nln = var.extent->range.start.line;
      if (nln != var.extent->range.end.line) {
        throw std::runtime_error("Multiline variable");
      }

      int16_t nscol = var.extent->range.start.column;
      int16_t necol = var.extent->range.end.column;

      auto& line = repro[nln];
      line = line.substr(0, nscol + 1) + std::string(var.detailed_name)
             + line.substr(necol);
    }
  }

  // Print the file
  for (auto const& s : repro) {
    std::cout << s << "\n";
  }

  return 0;
}
```

I started with variables, which turned out to be a lucky decision. The partially rebuilt file looked like this:

```cpp
   int std::TreeNode::val
   std::TreeNode *std::TreeNode::left
   std::TreeNode *std::TreeNode::right



   std::ustd::Co::context_t c
   char std::Co::stack[8192]
   std::TreeNode *std::Co::ret
      std::ucontext_t *link   void (*f)(std::Co *, ststd::TreeNode *root)         int b
                                                                            int l
                                                                            int e
                                                                            int s
                                                                            int s


              std::TreeNode *x                                                    int w
                                                                            int o
                                                                            int d



          std::Costd::TreeNode *x                                                       int w
                                                                            int h
                                                                            int o
                                                                            int i
                                                                            int s




                    std::TreeNode *root1   std::TreeNode *root2             int i
     std::ucontext_t c                                                            int n
     std::Co c2                                                   int h
                                                                            int k







             std::TreeNode std::TreeNode &y
```

You can immediately see a column of single-letter variables. After a few attempts, `blesswodwhoisinhk` turned out to be the correct flag.

## Addendum
But, what is this program actually trying to solve? It mentions "Leaf-Similar Trees" and "same-fringe". Apparently coroutines are a good way of solving it?

Simply put, two binary trees are leaf-similar if their leaves, read left-to-right, have the same values. You could also allow one to be a subset of the other. The naive solution is to first convert both trees to lists of their leaves, and then compare the lists. However, this is rather inefficient. What if they differ in the first value? We could have known the answer after one comparison, but we did two tree traversals. As a better alternative, coroutines allow a [quick and elegant solution](http://wiki.c2.com/?SameFringeProblem).
