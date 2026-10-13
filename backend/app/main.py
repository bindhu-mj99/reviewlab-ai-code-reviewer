from fastapi import FastAPI
from pydantic import BaseModel, Field
import ast, re
app=FastAPI(title="ReviewLab API")
class Review(BaseModel):
    code:str=Field(min_length=1,max_length=20000)
@app.get("/health")
def health(): return {"status":"ok"}
@app.post("/review")
def review(body:Review):
    code=body.code; findings=[]
    for pat,sev,msg in [(r"\beval\s*\(","high","Avoid eval() on untrusted input."),(r"\bexec\s*\(","high","Avoid exec() on untrusted input."),(r"(password|api_key|secret)\s*=\s*['\"][^'\"]+['\"]","high","Possible hard-coded secret."),(r"except\s*:","medium","Prefer a specific exception.")]:
        for m in re.finditer(pat,code,re.I): findings.append({"line":code.count("\n",0,m.start())+1,"severity":sev,"message":msg})
    try: ast.parse(code)
    except SyntaxError as e: findings.append({"line":e.lineno or 1,"severity":"high","message":"Syntax error: "+e.msg})
    if not findings: findings=[{"line":1,"severity":"info","message":"No basic rule violations found; not proof of correctness."}]
    return {"count":len(findings),"findings":findings}
