set -ex
owner=$(/usr/sbin/mdata-get owner)
zuuid=$(/usr/local/bin/zonename)
zalias=$(/usr/sbin/mdata-get sdc:alias)
find /var/www/htdocs -type f -name '*.erb' | while read tpl; do
  fname="$(dirname "${tpl}")/$(basename "${tpl}" .erb)"
  erb -T - \
    "owner=${owner}" \
    "zalias=${zalias}" \
    "zuuid=${zuuid}" \
    "${tpl}" > "${fname}"
   rm -f "${tpl}"
done
