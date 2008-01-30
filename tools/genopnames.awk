#!/usr/bin/awk -f

# rewritten from ruby version with the kind help of Soren Dossing

BEGIN{
	inside = -1;

	if (! (outf = ENVIRON["OUTF"])) {
		print "output file unspecified";
		exit 1;
	}

	while (getline)
	{
		if (inside == -1) {
			if ($0 ~ /^[[:space:]]*enum[[:space:]]+fuse_opcode[[:space:]]*\{/) 
				inside = 0;
			continue;
		}
		if ($0 ~ /^[[:space:]]*\}/)
			break;
		if (! ($0 ~ /^[[:space:]]*[A-Z_]+[[:space:]]*(,|=[[:space:]]*[[:digit:]]+)/))
			continue;
		sub(/,.*/,"");
		sub(/=/,"");
		$2 ? (inside = $2) : (inside += 1);
		if (ops[inside]) {
			print "colliding values for fuse opcodes:", inside, "<-", ops[inside], "vs.", $1 > "/dev/stderr";
			exit 1;
		}
		ops[inside] = $1;
	}

	print "/* Generated by an awk script from fuse_kernel.h, don't hand hack it! */" > outf;
	print "" >> outf;
	print "static char *fuse_opnames[] __attribute__((unused)) = {" >> outf;
	for (o=0; o <= inside; o++) {
		print ops[o] ? "\t\""ops[o]"\"," : "\tNULL," >> outf;
	};
	print "};" >> outf;;
	print "" >> outf;
	print "#define FUSE_OPTABLE_SIZE "inside + 1 >> outf;
}