class Solution:
    def findWords(self, board: List[List[str]], words: List[str]) -> List[str]:
        Rows=len(board)
        Cols=len(board[0])
        path=set()

        def dfs(r,c,w,i):
            if i==len(w): return True
            if (min(r,c) < 0 or
                r>=Rows or 
                c>=Cols or 
                board[r][c]!=w[i] or
                (r,c) in path):
                return False
            path.add((r,c))
            res= (dfs(r+1,c,w,i+1) or dfs(r-1,c,w,i+1) or dfs(r,c+1,w,i+1) or dfs(r,c-1,w,i+1))
            path.remove((r,c))
            return res
        res = []
        for word in words:
            found = False
            for r in range(Rows):
                for c in range(Cols):
                    if dfs(r, c, word, 0):
                        found = True
                        break
                if found and word:
                    break
            if word not in res:
                res.append(word)
        return res

