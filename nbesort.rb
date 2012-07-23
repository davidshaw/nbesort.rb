#!/usr/bin/ruby
"""
@Author	:	David Shaw
@Date	:	September 22, 2010
@Name	:	nbesort.rb
@Desc	:	This takes a nessus NBE file and arranges finding into
		a nice and pretty console output. Should be easier to
		create reports this way!
@Usage	:	ruby nbesort.rb <nessus nbe output>
@Notes	:
January 31, 2011
		Tenable updated NBE format. nbesort has been updated to
		accomodate these changes.

July 23, 2012
		Updated the script to not cut off synposis at 'fake' line
		break. Added text for 'Risk Factor' so 'none' makes more
		sense.

@TODO	:	msf exploitability search, nessus plugin ID reference

"""

puts """
  ____________ 
 < nbesort 0.3 >
  ------------
        \\   ^__^
         \\  (oo)\\
            (__)\\
"""
if ARGV.size != 1 then
	puts "Usage: ruby nbesort.rb <nessus nbe>"
	exit
end
                                                               
# global finding db
$findings = Hash.new {|h, k| h[k] = Array.new}

filename = ARGV[0]
puts "[-] opening #{filename}"
f = File.open(filename, "r") # user input

f.each_with_index do |line, index|
	# don't do any of this if the line is nil
	if line != nil then
		# regex out IP, finding synopsis
		host = line.scan(/results\|[^\|]+/)[0]
		if host
			p1 = line.index("|")
			p2 = line[(p1 + 1)..line.size].index("|") + p1 + 1
			p3 = line[(p2 + 1)..line.size].index("|") + p2 + 1
			host = line[p2 + 1..p3 - 1]
			host = host + ' -- ' + line.scan(/\d+\/tcp/)[0] if line.scan(/\d+\/tcp/)[0]
		end
		if line.include?('Synopsis :') then		
			title = line.scan(/Synopsis :\\n\\n([^:]+)/)[0]
			title[0] = title[0][0..-17]
			title[0].gsub!("\\n", " ")
			title.push("Risk Factor: " + line.scan(/Risk factor :\\n\\n([^\\]+)/)[0].to_s) 
		end
		line.scan(/\d+\/tcp/)[0]
		# add to the database
		$findings[title].push(host) if host and title
		host = nil
		title = nil
	end
end

$findings.each do |key, value|
	print "=> "
	puts key
	value.each do |e|
		puts e
	end
	puts 
end

