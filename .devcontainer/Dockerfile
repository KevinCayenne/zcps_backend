# For more information, please refer to https://aka.ms/vscode-docker-python
FROM python:3.12-slim

EXPOSE 8000

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1
# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create the user
RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME && \
    #
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    apt-get update && \
    apt-get install -y zip git curl wget jq sudo gcc g++ build-essential procps && \
    apt-get autoremove && \
    echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME

# Install pip requirements
COPY requirements*.txt .
RUN pip install -r requirements-dev.txt && \
    pip install django-debug-toolbar apig-wsgi ipykernel awscli

WORKDIR /workspace

# enable bash completion
RUN git clone --depth=1 https://github.com/Bash-it/bash-it.git ~/.bash_it && \
    ~/.bash_it/install.sh --silent && \
    rm ~/.bashrc.bak && \
    bash -i -c "bash-it enable completion git"

RUN echo 'eval "$(register-python-argcomplete sim)"' >> ~/.bashrc

# colorize less
RUN lesspipe >> ~/.bashrc && \
    echo "export LESS='-R'" >> ~/.bashrc && \
    echo "export PYGMENTIZE_STYLE='monokai'" >> ~/.bashrc && \
    curl -sSL https://raw.githubusercontent.com/CoeJoder/lessfilter-pygmentize/master/.lessfilter > ~/.lessfilter && \
    chmod 755 ~/.lessfilter

USER ${USERNAME}

SHELL ["/bin/bash", "-c"]

# During debugging, this entry point will be overridden. For more information, please refer to https://aka.ms/vscode-docker-python-debug
# File wsgi.py was not found. Please enter the Python path to wsgi file.
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
