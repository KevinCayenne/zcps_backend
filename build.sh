# /bin/sh
# Build lambda.zip

directory="tmp_venv"
artifact="artifact.zip"

if [ ! -d "$directory" ]; then
  mkdir -p "$directory"
  echo "Directory created: temp directory $directory"
fi

filtered_requirements=$(mktemp)
trap 'rm -f "$filtered_requirements"' EXIT

# Strip dj-rest-auth[with_social] before bulk install to avoid duplicate handling.
sed '/^dj-rest-auth\[with_social\]/d' requirements.txt > "$filtered_requirements"

pip install \
 --platform manylinux2014_x86_64 \
 --only-binary=:all: \
 --python-version 3.13 \
 --upgrade \
 --target $directory \
 -r "$filtered_requirements"

current_branch=$(git branch --show-current)
if [ "$current_branch" != "prod" ]; then
  echo "Current branch is not 'prod'."
  pip install \
    --platform manylinux2014_x86_64 \
    --no-deps --prefer-binary \
    --python-version 3.13 \
    --upgrade \
    --target $directory \
    django-debug-toolbar
fi

pip install \
 --platform manylinux2014_x86_64 \
 --no-deps --prefer-binary \
 --python-version 3.13 \
 --upgrade \
 --target $directory \
 apig-wsgi dj-rest-auth[with_social]

if [ -e "$artifact" ]; then
    rm "$artifact"
    echo "File removed: $artifact"
fi

cd $directory ; zip -r "../$artifact" . -x '*.pyc'
cd ..
zip "$artifact" lambda_function.py
zip -r "$artifact" announcement/ clinic/ config/ logs/ users/

if [ -d "$directory" ]; then
  rm -r "$directory"
  echo "Directory removed: temp directory $directory"
fi
