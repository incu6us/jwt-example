openssl genrsa -out sample_key.priv 2048
openssl rsa -in sample_key.priv -pubout > sample_key.pub
