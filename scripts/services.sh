
# If the user of directory challenges_db is not equal to the user at work, a permission error will occur when initializing the database.
db_name="challenges_db"
path=`pwd`
db_path=${path}/${db_name}
if [ -d $db_path ]
then
  echo "$db_path directory already exists"
  if [ -O $db_path ]
  then
    echo "$db_path directory belongs to the current user"
  else
    echo "$db_path directory does not belong to the current user, a permission error will occur when initializing the database"
    return
  fi
else
  echo "$db_path directory does not exist and will be newly created"
fi

rm services
rm services.log
cargo clean
cargo build --release --bin services
cp target/release/services .
nohup ./services --cache_srs_pk --generate_smart_contract > services.log 2>&1 &