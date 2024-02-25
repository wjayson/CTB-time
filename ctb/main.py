from turtle import clear
from flask import Flask,jsonify, render_template
from flask_wtf import FlaskForm
from flask_login import LoginManager
import pickle
import time

# ...
app = Flask(__name__)  # 创建 Flask 应用

app.secret_key = 'abc'  # 设置表单交互密钥

login_manager = LoginManager()  # 实例化登录管理对象
login_manager.init_app(app)  # 初始化应用
login_manager.login_view = 'login'  # 设置用户登录视图函数 endpoint




from werkzeug.security import generate_password_hash

USERS = []


input=open(r"C:\ctb\data.txt","rb")
USERS=pickle.load(input)
input.close()





from werkzeug.security import generate_password_hash
import uuid

def create_user(user_name, password):
    """创建一个用户"""
    user = {
        "name": user_name,
        "password": generate_password_hash(password),
        "id": uuid.uuid4()
    }
    USERS.append(user)
    output=open(r"C:\ctb\data.txt","wb")
    pickle.dump(USERS,output)
    output.close()


def get_user(user_name):
    """根据用户名获得用户记录"""
    for user in USERS:
        if user.get("name") == user_name:
            return user
    return None


from flask_login import UserMixin  # 引入用户基类
from werkzeug.security import check_password_hash

class User(UserMixin):
    """用户类"""
    def __init__(self, user):
        self.username = user.get("name")
        self.password_hash = user.get("password")
        self.id = user.get("id")

    def verify_password(self, password):
        """密码验证"""
        if self.password_hash is None:
            return False
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        """获取用户ID"""
        return self.id

    @staticmethod
    def get(user_id):

        """根据用户ID获取用户实体，为 login_user 方法提供支持"""
        if not user_id:
            return None
        for user in USERS:
            if user.get('id') == user_id:
                return User(user)
        return None

@login_manager.user_loader  # 定义获取登录用户的方法
def load_user(user_id):
    return User.get(user_id)

from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, EqualTo
# ...

class LoginForm(FlaskForm):
    """登录表单类"""
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])



from flask import render_template, redirect, url_for, request
from flask_login import login_user
# ...
@app.route('/login/', methods=('GET', 'POST'))  # 登录
def login():
    form = LoginForm()
    emsg = None
    if form.validate_on_submit():
        user_name = form.username.data
        password = form.password.data
        user_info = get_user(user_name) # 从用户数据中查找用户记录
        if user_info is None:
            emsg = "用户名或密码密码有误"
        else:
            user = User(user_info)  # 创建用户实体
            if user.verify_password(password):  # 校验密码
                login_user(user)  # 创建用户 Session
                return redirect(request.args.get('next') or url_for('grid'))
            else:
                emsg = "用户名或密码密码有误"
    return render_template('login.html', form=form, emsg=emsg)

from flask import render_template, url_for
from flask_login import current_user, login_required
# ...
tasks = []
input_task=open(r"C:\ctb\task.txt","rb")
tasks=pickle.load(input_task)
input_task.close()
#四象限

@app.route("/", methods = ['GET', 'POST'])
@login_required
def grid():
    name = current_user.username

    if request.method == "POST" and request.values.get("button1") == "submit": #此时获得用户的提交
        
        new_task = request.form.get("new_task")
            
            #获得优先级
        important_urgent = request.form.get("classification") == "important_urgent"
        important_not_urgent = request.form.get("classification") == "important_not_urgent"
        not_important_urgent = request.form.get("classification") == "not_important_urgent"
        not_important_not_urgent = request.form.get("classification") == "not_important_not_urgent"
        #进行分类 
        if important_urgent:
            tasks.append({"task": new_task, "priority": "important_urgent", "user": name})
        if important_not_urgent:
            tasks.append({"task": new_task, "priority": "important_not_urgent", "user": name})
        if not_important_urgent:
            tasks.append({"task": new_task, "priority": "not_important_urgent", "user": name })
        if not_important_not_urgent:
            tasks.append({"task": new_task, "priority": "not_important_not_urgent", "user": name})
    user_task = []
    for task in tasks:
        if task.get("user") == name:
            user_task.append(task)
    output_task=open(r'C:\ctb\task.txt','wb')
    pickle.dump(tasks,output_task)
    output_task.close()
    global user_completed_tasks
    clear_task = []
    if request.method == "POST" and request.values.get("button2") == "clear": #此时获得用户的清除请求
        for task in user_completed_tasks:
            if task["user"] == name:
                clear_task.append(user_completed_tasks[user_completed_tasks.index(task)])
        for task in clear_task:
            for completed_task in user_completed_tasks:
                if task == completed_task:
                    del user_completed_tasks[user_completed_tasks.index(task)]
    user_finished_list = []
    for task in user_completed_tasks:
        if task["user"] == name:
            user_finished_list.append(task["task"])
            
           
            

    
    return render_template("index_2.html", name = name, user_task = user_task, user_completed_tasks = user_completed_tasks, tasks = tasks, finished_task_number = len(user_finished_list))
  

completed_tasks = []
user_completed_tasks = []
#番茄钟
@app.route('/timer')
@login_required
def timer():
    return render_template('index_3.html')

@app.route('/todo')
@login_required
def todo():
    return render_template('index_5.html')


@app.route("/update", methods = ['POST'])
@login_required
def update_website():
    name = current_user.username
    task_index = int(request.form.get("index"))
    user_completed_tasks.append({"task":tasks[task_index]["task"], "user":name})
    del tasks[task_index]
    return jsonify({"success": True})
  

from flask import redirect, url_for
from flask_login import logout_user
# ...
@app.route('/logout')  # 登出
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods = ['GET', 'POST'])
def register():
    repeat = False
    display = False
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        for user in USERS:
            if user["name"] == username:
                repeat = True
                display = True
                break
            else:    

                repeat = False
                display = True
        if not repeat:
            create_user(username, password)
    return render_template("register.html", repeat = repeat, display = display)


@app.route('/ranking', methods = ['GET', 'POST'])
@login_required
def ranking():
    name = current_user.username
    ranking_list = []
    initial_score = 0
    for user in USERS:
        ranking_list.append({"user": user["name"], "score": initial_score, "rank": 1})
    for task in user_completed_tasks:
        for user in ranking_list:
            if task["user"] == user["user"]:
                user["score"] += 200
    score_lst = []
    for score in ranking_list:
        score_lst.append(score["score"])
    score_lst.sort(reverse=True)
    for user in ranking_list:
        user["rank"] = score_lst.index(user["score"]) + 1
             
    return render_template("ranking.html", ranking_list = ranking_list, user_number = len(USERS) + 1, name =name)
        



if __name__ == '__main__':
    app.run() 



