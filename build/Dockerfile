FROM python:alpine

# 设置环境变量
ENV PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production

# 安装Python依赖并创建用户
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple flask==2.3.3 PyJWT==2.8.0 && \
    adduser -D -h /home/ctf ctf && \
    mkdir -p /home/ctf/app

# 复制应用文件
COPY app.py /home/ctf/app/

# 设置工作目录和权限
WORKDIR /home/ctf/app
RUN chown -R ctf:ctf /home/ctf/app

# 切换到非root用户
USER ctf

# 启动应用
CMD ["python", "app.py"]